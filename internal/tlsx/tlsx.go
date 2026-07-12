// Package tlsx содержит вспомогательные функции для TLS: обёртку сервера с
// выдачей сертификатов «на лету», конфиг для небезопасных исходящих соединений
// и разбор SNI из ClientHello без расшифровки.
package tlsx

import (
	"crypto/tls"
	"net"
)

// GetCertFunc — callback выдачи сертификата по SNI (совместим с tls.Config).
type GetCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// Server оборачивает клиентское соединение в TLS-сервер, выдавая сертификаты
// «на лету» через callback. Согласуются протоколы h2 и http/1.1.
func Server(conn net.Conn, getCert GetCertFunc) *tls.Conn {
	cfg := &tls.Config{
		GetCertificate: getCert,
		MinVersion:     tls.VersionTLS10,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	return tls.Server(conn, cfg)
}

// InsecureConfig — конфиг исходящих соединений с отключённой проверкой
// сертификата апстрима (флаг --insecure).
func InsecureConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"http/1.1"},
	}
}
