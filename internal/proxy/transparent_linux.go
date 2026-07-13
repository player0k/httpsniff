//go:build linux

package proxy

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"httpsniff/internal/i18n"
)

const soOriginalDst = 80

// markHex — hex-значение SO_MARK для iptables (должно совпадать с proxyMark в mark_linux.go).
const markHex = "0xdead"

var (
	iptMu       sync.Mutex
	iptApplied  bool
	iptPort     string
)

// ServeTransparent запускает прозрачный перехват TCP: автоматически настраивает
// iptables REDIRECT для TCP 80/443 → указанный порт, клиенты обслуживаются
// с определением исходного адреса назначения через SO_ORIGINAL_DST.
func (p *Proxy) ServeTransparent(addr string, tport int) (func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serveTransparentConn(conn)
		}
	}()

	if err := setupIptables(tport); err != nil {
		ln.Close()
		return nil, err
	}

	fmt.Printf("\033[2m%s\033[0m\n", i18n.T("proxy.transparentLinuxActive", addr, tport))

	return func() {
		ln.Close()
		restoreIptables()
	}, nil
}

// setupIptables добавляет правила REDIRECT для перенаправления TCP 80/443
// на указанный порт прозрачного прокси. Исходящие пакеты прокси (с SO_MARK)
// пропускаются, чтобы не создавать бесконечный цикл.
func setupIptables(port int) error {
	iptMu.Lock()
	defer iptMu.Unlock()

	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("%s", i18n.T("proxy.errIptablesNotFound"))
	}

	portStr := strconv.Itoa(port)

	// Удаляем старые правила (если есть).
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-m", "mark", "--mark", markHex, "-j", "RETURN").Run()
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "-m", "multiport", "--dports", "80,443",
		"-j", "REDIRECT", "--to-ports", portStr).Run()

	// Правило 1: помеченные пакеты прокси (SO_MARK) — пропускаем (RETURN),
	// чтобы исходящие соединения прокси к апстриму не зациклились.
	argsMark := []string{
		"-t", "nat", "-A", "OUTPUT",
		"-m", "mark", "--mark", markHex,
		"-j", "RETURN",
	}
	if out, err := exec.Command("iptables", argsMark...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", i18n.T("proxy.errIptablesSetup", ""), string(out))
	}

	// Правило 2: всё остальное TCP 80/443 — перенаправляем на прокси.
	argsAdd := []string{
		"-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "-m", "multiport", "--dports", "80,443",
		"-j", "REDIRECT", "--to-ports", portStr,
	}
	if out, err := exec.Command("iptables", argsAdd...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s", i18n.T("proxy.errIptablesSetup", string(out)))
	}

	iptApplied = true
	iptPort = portStr
	return nil
}

// restoreIptables удаляет правила REDIRECT и mark, добавленные при запуске.
func restoreIptables() {
	iptMu.Lock()
	defer iptMu.Unlock()

	if !iptApplied || iptPort == "" {
		return
	}

	// Удаляем правило REDIRECT.
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "-m", "multiport", "--dports", "80,443",
		"-j", "REDIRECT", "--to-ports", iptPort).Run()

	// Удаляем правило mark-exclusion.
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-m", "mark", "--mark", markHex,
		"-j", "RETURN").Run()

	iptApplied = false
	iptPort = ""
}

func (p *Proxy) serveTransparentConn(conn net.Conn) {
	dst, err := originalDst(conn)
	if err != nil {
		conn.Close()
		return
	}
	pid := p.clientPID(conn)
	p.HandleTransparent(conn, dst, pid)
}

// originalDst извлекает исходный адрес назначения перенаправленного соединения.
func originalDst(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("не TCP-соединение")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}

	var result string
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		var sa unix.RawSockaddrInet4
		sz := uint32(unsafe.Sizeof(sa))
		_, _, e := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&sa)),
			uintptr(unsafe.Pointer(&sz)),
			0,
		)
		if e != 0 {
			sockErr = e
			return
		}
		ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
		port := (sa.Port >> 8) | (sa.Port << 8) // ntohs
		result = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	})
	if err != nil {
		return "", err
	}
	if sockErr != nil {
		return "", sockErr
	}
	return result, nil
}
