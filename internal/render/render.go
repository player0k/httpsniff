// Package render форматирует перехваченный обмен (запрос/ответ) в цветной
// текстовый блок с ANSI-кодами для вывода в TUI/поток и в файл (без цветов).
package render

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"httpsniff/internal/i18n"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI убирает ANSI-цвета (для записи в файл).
func StripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// Exchange форматирует полный HTTP-обмен: строку запроса, заголовки и тело в обе
// стороны. maxBody ограничивает выводимое тело (0 = без ограничения).
func Exchange(id uint64, pid int, req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, maxBody int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n\033[1;36m════════ #%d  PID=%s  %s ════════\033[0m\n", id, pidStr(pid), time.Now().Format("15:04:05.000"))

	fmt.Fprintf(&b, "\033[1;32m▶ %s\033[0m %s %s %s\n", i18n.T("log.request"), req.Method, req.URL.String(), reqProto(req))
	writeHeaders(&b, req.Header)
	writeBody(&b, i18n.T("log.requestBody"), req.Header.Get("Content-Encoding"), reqBody, maxBody)

	fmt.Fprintf(&b, "\033[1;33m◀ %s\033[0m %s %s\n", i18n.T("log.response"), resp.Proto, resp.Status)
	writeHeaders(&b, resp.Header)
	writeBody(&b, i18n.T("log.responseBody"), resp.Header.Get("Content-Encoding"), respBody, maxBody)

	fmt.Fprint(&b, "\033[1;36m────────────────────────────────────────\033[0m\n")
	return b.String()
}

// TLSPassthrough форматирует запись о HTTPS-соединении без расшифровки
// (виден только хост из SNI).
func TLSPassthrough(id uint64, pid int, host, origDst string) string {
	name := host
	if name == "" {
		name = origDst
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\033[1;36m════════ #%d  PID=%s  %s ════════\033[0m\n", id, pidStr(pid), time.Now().Format("15:04:05.000"))
	fmt.Fprintf(&b, "\033[1;35m▶ HTTPS\033[0m %s  →  %s  \033[2m%s\033[0m\n", name, origDst, i18n.T("log.httpsNoDecrypt"))
	fmt.Fprintf(&b, "\033[2m  %s\033[0m\n", i18n.T("log.httpsNote"))
	fmt.Fprint(&b, "\033[1;36m────────────────────────────────────────\033[0m\n")
	return b.String()
}

// RequestError форматирует строку об ошибке форвардинга запроса на апстрим.
func RequestError(pid int, req *http.Request, err error) string {
	return fmt.Sprintf("\033[1;31m✗ PID=%s %s %s — %s\033[0m\n", pidStr(pid), req.Method, req.URL.String(), i18n.T("log.error", err))
}

// MITMRejected форматирует запись об отклонённом приложением MITM-рукопожатии
// (сертификат не доверен; дальше по этому хосту — проброс).
// Для Flutter на Windows auto-unpin попытается пропатчить процесс;
// для curl/браузеров нужен доверенный CA в системном store.
func MITMRejected(pid int, host string, err error) string {
	return fmt.Sprintf("\033[1;31m✗ PID=%s %s: %v\033[0m\n", pidStr(pid), i18n.T("log.mitmRejected", host), err)
}

func reqProto(r *http.Request) string {
	if r.ProtoMajor == 2 {
		return "HTTP/2"
	}
	if r.Proto != "" {
		return r.Proto
	}
	return "HTTP/1.1"
}

func writeHeaders(b *strings.Builder, h http.Header) {
	for k, vals := range h {
		for _, v := range vals {
			fmt.Fprintf(b, "  \033[2m%s:\033[0m %s\n", k, v)
		}
	}
}

func writeBody(b *strings.Builder, label, encoding string, body []byte, maxBody int) {
	if len(body) == 0 {
		return
	}
	decoded, encNote := decodeBody(encoding, body)

	fmt.Fprintf(b, "  \033[1m%s\033[0m (%d %s", label, len(body), i18n.T("log.bytes"))
	if encNote != "" {
		fmt.Fprintf(b, ", %s", i18n.T("log.decoded", encNote))
	}
	fmt.Fprint(b, ")\n")

	if !isMostlyText(decoded) {
		fmt.Fprintf(b, "  \033[2m%s\033[0m\n", i18n.T("log.binary", len(decoded)))
		return
	}

	shown := decoded
	truncated := false
	if maxBody > 0 && len(shown) > maxBody {
		shown = shown[:maxBody]
		truncated = true
	}
	for _, line := range strings.Split(string(shown), "\n") {
		fmt.Fprintf(b, "  │ %s\n", line)
	}
	if truncated {
		fmt.Fprintf(b, "  \033[2m%s\033[0m\n", i18n.T("log.truncated", maxBody, len(decoded)))
	}
}

func pidStr(pid int) string {
	if pid <= 0 {
		return "?"
	}
	return strconv.Itoa(pid)
}
