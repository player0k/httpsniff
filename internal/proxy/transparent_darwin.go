//go:build darwin

package proxy

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"httpsniff/internal/i18n"
)

// ServeTransparent запускает прозрачный перехват TCP на macOS через пакетный
// фильтр pf. Клиенты, чей трафик перенаправлен правилом `rdr` на локальный порт
// перехватчика, обслуживаются с восстановлением исходного адреса назначения
// через ioctl DIOCNATLOOK на /dev/pf (аналог SO_ORIGINAL_DST в Linux).
//
// Требуется запуск от root (чтение /dev/pf) и настроенное правило pf, например:
//
//	echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port 8889' | sudo pfctl -ef -
//
// Для перехвата собственного исходящего трафика правило вешают на нужный
// интерфейс (en0 и т. п.).
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
		ln.Close()
		pf.Close()
	}, nil
}

func (p *Proxy) serveTransparentConn(conn net.Conn, pf *os.File) {
	dst, err := originalDstPF(conn, pf)
	if err != nil {
		conn.Close()
		return
	}
	pid := p.clientPID(conn)
	p.HandleTransparent(conn, dst, pid)
}

// ---- pf DIOCNATLOOK ----

// diocNatlook — _IOWR('D', 23, struct pfioc_natlook); размер структуры 76 байт.
const diocNatlook = 0xc04c4417

const pfOut = 2 // PF_OUT

// pfiocNatlook повторяет struct pfioc_natlook из <net/pfvar.h> (macOS, 76 байт,
// без внутренних выравниваний: 4×16 + 4×2 + 4×1).
type pfiocNatlook struct {
	saddr    [16]byte
	daddr    [16]byte
	rsaddr   [16]byte
	rdaddr   [16]byte
	sxport   uint16
	dxport   uint16
	rsxport  uint16
	rdxport  uint16
	af       uint8
	proto    uint8
	protoVar uint8
	dir      uint8
}

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
	nl.sxport = htons(uint16(src.Port))
	nl.dxport = htons(uint16(dst.Port))
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
	port := ntohs(nl.rdxport)
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

// htons/ntohs переводят порт в/из сетевого порядка байтов. Все поддерживаемые
// macOS-архитектуры (amd64, arm64) — little-endian, поэтому просто меняем байты.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
