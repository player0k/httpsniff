package render

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// decodeBody распаковывает тело согласно Content-Encoding для отображения.
// Возвращает распакованные данные и краткую пометку о кодировке.
func decodeBody(encoding string, body []byte) ([]byte, string) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		if r, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if d, err := io.ReadAll(r); err == nil {
				return d, "gzip"
			}
		}
	case "deflate":
		if r, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			if d, err := io.ReadAll(r); err == nil {
				return d, "deflate(zlib)"
			}
		}
		r := flate.NewReader(bytes.NewReader(body))
		if d, err := io.ReadAll(r); err == nil {
			return d, "deflate(raw)"
		}
	case "", "identity":
		return body, ""
	case "br":
		r := brotli.NewReader(bytes.NewReader(body))
		if d, err := io.ReadAll(r); err == nil {
			return d, "br"
		}
		return body, ""
	}
	return body, ""
}

// isMostlyText эвристически определяет, можно ли безопасно показать данные как
// текст (мало непечатаемых байт в первых 2 КБ).
func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	n := len(b)
	if n > 2048 {
		n = 2048
	}
	nonPrintable := 0
	for _, c := range b[:n] {
		if c == 9 || c == 10 || c == 13 {
			continue
		}
		if c < 32 || c == 127 {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(n) < 0.10
}
