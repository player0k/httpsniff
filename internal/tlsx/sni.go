package tlsx

import "encoding/binary"

// ParseClientHelloSNI извлекает имя хоста (SNI) из TLS ClientHello.
// Возвращает host и true при успехе. Работает по «подсмотренным» первым байтам
// соединения, не расшифровывая трафик.
func ParseClientHelloSNI(b []byte) (string, bool) {
	// TLS record: type(1)=0x16, version(2), length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	body := b[5:]
	if recLen < len(body) {
		body = body[:recLen]
	}
	// Handshake: type(1)=0x01 ClientHello, length(3)
	if len(body) < 4 || body[0] != 0x01 {
		return "", false
	}
	p := body[4:]
	// client_version(2) + random(32)
	if len(p) < 34 {
		return "", false
	}
	p = p[34:]
	// session_id
	if len(p) < 1 {
		return "", false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return "", false
	}
	p = p[sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < csLen {
		return "", false
	}
	p = p[csLen:]
	// compression_methods
	if len(p) < 1 {
		return "", false
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", false
	}
	p = p[cmLen:]
	// extensions
	if len(p) < 2 {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < extTotal {
		extTotal = len(p)
	}
	p = p[:extTotal]

	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[0:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < extLen {
			return "", false
		}
		ext := p[:extLen]
		p = p[extLen:]
		if extType != 0x0000 { // server_name
			continue
		}
		// server_name_list(2), затем записи: type(1), len(2), name
		if len(ext) < 2 {
			return "", false
		}
		listLen := int(binary.BigEndian.Uint16(ext[0:2]))
		names := ext[2:]
		if listLen < len(names) {
			names = names[:listLen]
		}
		for len(names) >= 3 {
			nType := names[0]
			nLen := int(binary.BigEndian.Uint16(names[1:3]))
			names = names[3:]
			if len(names) < nLen {
				return "", false
			}
			if nType == 0x00 { // host_name
				return string(names[:nLen]), true
			}
			names = names[nLen:]
		}
	}
	return "", false
}
