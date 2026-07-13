//go:build !linux

package proxy

import (
	"context"
	"net"
)

// markedDialContext — заглушка для не-Linux платформ (SO_MARK не нужен).
func markedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
