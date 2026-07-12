package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/quic-go/quic-go/http3"

	"httpsniff/internal/i18n"
)

// ServeQUIC поднимает MITM-сервер HTTP/3 (QUIC) на локальном UDP-порту.
// Трафик на этот порт должен направляться прозрачным редиректом UDP:443
// (WinDivert на Windows / iptables на Linux). Клиент видит наш сертификат,
// запрос декодируется и форвардится на реальный сервер.
func (p *Proxy) ServeQUIC(port int) (func(), error) {
	tlsConf := &tls.Config{
		GetCertificate: p.ca.GetCertificate,
		NextProtos:     []string{http3.NextProtoH3},
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return nil, err
	}
	srv := &http3.Server{
		TLSConfig: tlsConf,
		Handler:   p.h3Handler(),
	}
	go srv.Serve(pc)

	fmt.Printf("\033[2m%s\033[0m\n", i18n.T("proxy.quicListen", port))

	return func() {
		srv.Close()
		pc.Close()
	}, nil
}

// h3Handler форвардит HTTP/3-запрос через общий core и отвечает клиенту по HTTP/3.
// Для QUIC-потоков PID пока не определяется — логируем всё (pid = -1).
func (p *Proxy) h3Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.forward(w, r, "https", r.Host, true, -1)
	}
}
