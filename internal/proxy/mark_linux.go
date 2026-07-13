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

// markedDialContext — DialContext, устанавливающий SO_MARK на каждый новый сокет.
func markedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		raw, err := tc.SyscallConn()
		if err == nil {
			raw.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMark)
			})
		}
	}
	return conn, nil
}
