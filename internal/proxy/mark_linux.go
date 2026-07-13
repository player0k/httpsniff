//go:build linux

package proxy

import (
	"context"
	"net"
	"syscall"
)

// proxyMark — значение SO_MARK, которое ставится на исходящие сокеты прокси,
// чтобы iptables не перенаправлял их обратно на себя (защита от циклов).
const proxyMark = 0xdead

// markedDialContext — DialContext, устанавливающий SO_MARK на сокет
// ДО вызова connect(), чтобы SYN-пакет уже уходил с пометкой и не попадал
// в правило REDIRECT.
func markedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	d.Control = func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMark)
		})
	}
	return d.DialContext(ctx, network, addr)
}
