//go:build darwin

package proxy

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"httpsniff/internal/i18n"
)

const pfAnchor = "com.apple/httpsniff"

var pfTokenRE = regexp.MustCompile(`(?i)token\s*:\s*(\d+)`)

// ServeTransparent запускает прозрачный перехват TCP на macOS через пакетный
// фильтр pf. Клиенты, чей трафик перенаправлен правилом `rdr` на локальный порт
// перехватчика, обслуживаются с восстановлением исходного адреса назначения
// через ioctl DIOCNATLOOK на /dev/pf (аналог SO_ORIGINAL_DST в Linux).
//
// Требуется запуск от root. Правила загружаются в отдельный системный anchor и
// удаляются при остановке. Исходящие соединения самого httpsniff исключаются,
// чтобы прокси не перенаправлял сам себя по кругу.
func (p *Proxy) ServeTransparent(addr string, tport int) (func(), error) {
	// Проверяем доступ к /dev/pf заранее, чтобы дать понятную ошибку.
	pf, err := os.OpenFile("/dev/pf", os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("proxy.errPfOpen"), err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pf.Close()
		return nil, err
	}

	pfStop, err := enableTransparentPF(tport, os.Geteuid())
	if err != nil {
		ln.Close()
		pf.Close()
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serveTransparentConn(conn, pf)
		}
	}()

	fmt.Printf("\033[2m%s\033[0m\n", i18n.T("proxy.transparentMacOS", addr, tport))

	return func() {
		pfStop()
		ln.Close()
		pf.Close()
	}, nil
}

// transparentPFRules сначала отправляет локальные исходящие TCP-пакеты в lo0.
// При повторном входе через lo0 rdr перенаправляет их в listener. rdr в PF
// применяется только ко входящим пакетам, поэтому одного rdr-правила мало.
func transparentPFRules(tport, proxyUID int) string {
	return fmt.Sprintf(`rdr pass on lo0 inet proto tcp from any to any port { 80, 443 } -> 127.0.0.1 port %d
pass out route-to lo0 inet proto tcp from any to any port { 80, 443 } user != %d
`, tport, proxyUID)
}

// enableTransparentPF загружает правила в com.apple/*: этот wildcard-anchor
// уже объявлен в штатном /etc/pf.conf macOS. Главный ruleset не заменяется.
// -E/-X используют reference token, поэтому мы не выключим PF, нужный другой
// системной службе.
func enableTransparentPF(tport, proxyUID int) (func(), error) {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return nil, fmt.Errorf("pfctl: %w", err)
	}

	rules := transparentPFRules(tport, proxyUID)
	load := exec.Command("pfctl", "-a", pfAnchor, "-f", "-")
	load.Stdin = strings.NewReader(rules)
	var loadErr bytes.Buffer
	load.Stderr = &loadErr
	if err := load.Run(); err != nil {
		return nil, fmt.Errorf("pfctl: %w: %s", err, strings.TrimSpace(loadErr.String()))
	}

	out, err := exec.Command("pfctl", "-E").CombinedOutput()
	if err != nil {
		exec.Command("pfctl", "-a", pfAnchor, "-F", "all").Run()
		return nil, fmt.Errorf("pfctl -E: %w: %s", err, strings.TrimSpace(string(out)))
	}
	tokenMatch := pfTokenRE.FindStringSubmatch(string(out))
	if len(tokenMatch) != 2 {
		exec.Command("pfctl", "-a", pfAnchor, "-F", "all").Run()
		return nil, fmt.Errorf("pfctl -E: enable token not found: %s", strings.TrimSpace(string(out)))
	}
	token := tokenMatch[1]

	var once bool
	return func() {
		if once {
			return
		}
		once = true
		exec.Command("pfctl", "-a", pfAnchor, "-F", "all").Run()
		exec.Command("pfctl", "-X", token).Run()
	}, nil
}

func (p *Proxy) serveTransparentConn(conn net.Conn, pf *os.File) {
	dst, err := originalDstPF(conn, pf)
	if err != nil {
		p.emit(fmt.Sprintf("\033[1;31m  transparent: original destination lookup failed for %s: %v\033[0m\n", conn.RemoteAddr(), err))
		conn.Close()
		return
	}
	pid := p.clientPID(conn)
	p.HandleTransparent(conn, dst, pid)
}

// ---- pf DIOCNATLOOK ----

const pfOut = 2 // PF_OUT

// pfStateXport повторяет union pf_state_xport из актуального XNU. Раньше union
// содержал только 16-битные порты; поле spi расширило его до четырёх байт.
type pfStateXport struct {
	port uint16
	_pad uint16
}

// pfiocNatlook повторяет struct pfioc_natlook из <net/pfvar.h> актуального XNU
// (84 байта: 4×16 адресов + 4×4 xport + 4 однобайтовых поля).
type pfiocNatlook struct {
	saddr    [16]byte
	daddr    [16]byte
	rsaddr   [16]byte
	rdaddr   [16]byte
	sxport   pfStateXport
	dxport   pfStateXport
	rsxport  pfStateXport
	rdxport  pfStateXport
	af       uint8
	proto    uint8
	protoVar uint8
	dir      uint8
}

// _IOWR('D', 23, struct pfioc_natlook). Размер вычисляется из Go-структуры,
// чтобы следующая ABI-ошибка не маскировалась захардкоженной константой.
const diocNatlook = uintptr(0xc0000000) |
	uintptr(unsafe.Sizeof(pfiocNatlook{}))<<16 |
	uintptr('D')<<8 | 23

// originalDstPF восстанавливает исходный адрес назначения перенаправленного
// соединения, спрашивая у pf по паре (источник клиента, локальный адрес прокси).
// Поддерживается только IPv4 (как и в Linux-реализации).
func originalDstPF(conn net.Conn, pf *os.File) (string, error) {
	src, ok := conn.RemoteAddr().(*net.TCPAddr) // источник клиента
	if !ok {
		return "", fmt.Errorf("не TCP-соединение")
	}
	dst, ok := conn.LocalAddr().(*net.TCPAddr) // адрес, куда pf завернул (наш прокси)
	if !ok {
		return "", fmt.Errorf("не TCP-соединение")
	}
	src4, dst4 := src.IP.To4(), dst.IP.To4()
	if src4 == nil || dst4 == nil {
		return "", fmt.Errorf("поддерживается только IPv4")
	}

	var nl pfiocNatlook
	copy(nl.saddr[:4], src4)
	copy(nl.daddr[:4], dst4)
	nl.sxport.port = htons(uint16(src.Port))
	nl.dxport.port = htons(uint16(dst.Port))
	nl.af = unix.AF_INET
	nl.proto = unix.IPPROTO_TCP
	nl.dir = pfOut

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		pf.Fd(),
		uintptr(diocNatlook),
		uintptr(unsafe.Pointer(&nl)),
	)
	if errno != 0 {
		return "", fmt.Errorf("DIOCNATLOOK: %w", errno)
	}

	ip := net.IPv4(nl.rdaddr[0], nl.rdaddr[1], nl.rdaddr[2], nl.rdaddr[3])
	port := ntohs(nl.rdxport.port)
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

// htons/ntohs переводят порт в/из сетевого порядка байтов. Все поддерживаемые
// macOS-архитектуры (amd64, arm64) — little-endian, поэтому просто меняем байты.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
