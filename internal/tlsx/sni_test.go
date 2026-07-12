package tlsx

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestParseSNI генерирует настоящий TLS ClientHello и проверяет извлечение SNI.
func TestParseSNI(t *testing.T) {
	c, s := net.Pipe()
	go func() {
		tls.Client(c, &tls.Config{ServerName: "api.example.com"}).Handshake()
	}()
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := s.Read(buf)
	c.Close()
	s.Close()

	host, ok := ParseClientHelloSNI(buf[:n])
	if !ok {
		t.Fatalf("SNI не распознан из %d байт", n)
	}
	if host != "api.example.com" {
		t.Fatalf("ожидался api.example.com, получено %q", host)
	}
}

func TestParseSNINotTLS(t *testing.T) {
	if _, ok := ParseClientHelloSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("HTTP-запрос ошибочно распознан как TLS")
	}
}
