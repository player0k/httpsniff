// Package tlsx содержит вспомогательные функции для TLS: обёртку сервера с
// выдачей сертификатов «на лету», конфиг для небезопасных исходящих соединений
// и разбор SNI из ClientHello без расшифровки.
package tlsx

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
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

// ReadClientHello читает из conn первый TLS record (ClientHello),
// возвращает сырые байты полной записи (включая 5-байтовый заголовок)
// и извлечённый SNI. conn должен быть в момент первого ClientHello.
func ReadClientHello(conn net.Conn) (raw []byte, sni string, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, "", err
	}
	if header[0] != 0x16 {
		return nil, "", fmt.Errorf("not a TLS handshake record: %x", header[0])
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, "", err
	}
	raw = append(header, body...)
	sni, _ = ParseClientHelloSNI(raw)
	return raw, sni, nil
}

// ReplayConn — обёртка над net.Conn, которая перед первым Read отдаёт
// сохранённые байты (например, заранее прочитанный ClientHello),
// а затем читает из оригинального соединения.
type ReplayConn struct {
	net.Conn
	replay []byte
}

func NewReplayConn(conn net.Conn, replay []byte) *ReplayConn {
	r := make([]byte, len(replay))
	copy(r, replay)
	return &ReplayConn{Conn: conn, replay: r}
}

func (c *ReplayConn) Read(p []byte) (int, error) {
	if len(c.replay) > 0 {
		n := copy(p, c.replay)
		c.replay = c.replay[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
