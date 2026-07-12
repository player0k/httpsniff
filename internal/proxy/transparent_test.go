package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"httpsniff/internal/ca"
)

// TestTransparentSNIPassthrough проверяет режим для Flutter: HTTPS не ломается
// MITM'ом, а прозрачно пробрасывается на реальный сервер; SNI-хост извлекается.
func TestTransparentSNIPassthrough(t *testing.T) {
	authority, err := ca.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := New(authority, 0, 4096, false) // tlsMITM=false по умолчанию

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.HandleTransparent(conn, "example.com:443", 0)
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	// TLS с SNI example.com — рукопожатие идёт со СВЯЗЬЮ до реального сервера
	// (проброс). Проверка против системных корней => сертификат настоящий.
	tconn := tls.Client(raw, &tls.Config{ServerName: "example.com"})
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("TLS-рукопожатие через проброс не удалось: %v", err)
	}
	if cs := tconn.ConnectionState(); len(cs.PeerCertificates) > 0 {
		t.Logf("сертификат сервера выдан: %s", cs.PeerCertificates[0].Issuer.CommonName)
	}

	fmt.Fprint(tconn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 128)
	n, _ := tconn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		t.Fatalf("нет HTTP-ответа через проброс, получено: %q", string(buf[:n]))
	}
	t.Logf("ответ: %s", strings.SplitN(string(buf[:n]), "\r\n", 2)[0])
}
