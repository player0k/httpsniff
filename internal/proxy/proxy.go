// Package proxy реализует MITM-прокси для HTTP/1.0, HTTP/1.1, HTTP/2 и HTTP/3:
// расшифровку TLS «на лету», фильтрацию по дереву процессов (PID) и вывод
// перехваченного обмена через абстракцию Logger.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"httpsniff/internal/ca"
	"httpsniff/internal/procinfo"
	"httpsniff/internal/render"
	"httpsniff/internal/tlsx"
)

// Logger — приёмник отформатированных блоков лога (реализуется слоем UI).
type Logger interface {
	Log(block string)
}

// Proxy — MITM-прокси. Нулевое значение непригодно; используйте New.
type Proxy struct {
	ca        *ca.Authority
	filterPID atomic.Int64 // 0 => перехватывать все процессы; меняется хоткеем на лету
	maxBody   int
	insecure  bool
	transport *http.Transport
	h2srv     *http2.Server

	logMu      sync.Mutex
	counter    atomic.Uint64
	logger     Logger
	logFile    *os.File
	tlsMITM    bool     // в прозрачном режиме: MITM HTTPS (true) или SNI+проброс (false)
	mitmFailed sync.Map // host(SNI) -> struct{}: где MITM отклонён, дальше — проброс

	parentsMu    sync.Mutex
	parentsCache map[int]int
	parentsAt    time.Time
}

// New создаёт прокси, подписывающий MITM-сертификаты через переданный CA.
func New(authority *ca.Authority, filterPID, maxBody int, insecure bool) *Proxy {
	tr := &http.Transport{
		DisableCompression:    true, // получаем тело как есть, декодируем сами
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true, // разрешаем HTTP/2 к вышестоящему серверу
	}
	if insecure {
		tr.TLSClientConfig = tlsx.InsecureConfig()
	}
	p := &Proxy{
		ca:        authority,
		maxBody:   maxBody,
		insecure:  insecure,
		transport: tr,
		h2srv:     &http2.Server{},
	}
	p.filterPID.Store(int64(filterPID))
	return p
}

// SetLogger назначает приёмник лога (TUI или обычный поток).
func (p *Proxy) SetLogger(l Logger) { p.logger = l }

// SetLogFile включает дублирование лога в файл (без ANSI-цветов).
func (p *Proxy) SetLogFile(f *os.File) { p.logFile = f }

// LoggingToFile сообщает, включено ли дублирование лога в файл.
func (p *Proxy) LoggingToFile() bool { return p.logFile != nil }

// SetTLSMITM управляет поведением HTTPS в прозрачном режиме: true — расшифровывать
// (MITM), false — только SNI-хост и прозрачный проброс (не ломает Flutter/Dart).
func (p *Proxy) SetTLSMITM(v bool) { p.tlsMITM = v }

// FilterPID возвращает текущий PID-фильтр (0 = все процессы).
func (p *Proxy) FilterPID() int { return int(p.filterPID.Load()) }

// SetFilterPID задаёт PID-фильтр во время работы (0 = все процессы).
func (p *Proxy) SetFilterPID(pid int) { p.filterPID.Store(int64(pid)) }

// matches сообщает, нужно ли перехватывать соединение процесса pid: истина, если
// фильтр не задан, либо pid равен целевому, либо является его потомком (дерево).
func (p *Proxy) matches(pid int) bool {
	root := p.FilterPID()
	if root == 0 {
		return true
	}
	if pid <= 0 {
		return false
	}
	pm := p.parents()
	cur := pid
	for depth := 0; depth < 64 && cur > 4; depth++ {
		if cur == root {
			return true
		}
		ppid, ok := pm[cur]
		if !ok || ppid == cur {
			break
		}
		cur = ppid
	}
	return cur == root
}

func (p *Proxy) parents() map[int]int {
	p.parentsMu.Lock()
	defer p.parentsMu.Unlock()
	if p.parentsCache == nil || time.Since(p.parentsAt) > time.Second {
		p.parentsCache = procinfo.ParentMap()
		p.parentsAt = time.Now()
	}
	return p.parentsCache
}

// ListenAndServe запускает прокси в режиме HTTP-прокси (CONNECT + абсолютные URL).
func (p *Proxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handleProxyConn(conn)
	}
}

// handleProxyConn обслуживает соединение в режиме явного HTTP-прокси.
func (p *Proxy) handleProxyConn(conn net.Conn) {
	defer conn.Close()

	pid := p.clientPID(conn)
	capture := p.matches(pid)

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req.URL.Host, capture, pid)
		return
	}

	// Обычный (незашифрованный) HTTP-прокси-запрос с абсолютным URL.
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if !p.roundtripH1(conn, req, "http", req.URL.Host, capture, pid) {
		return
	}
	p.serveH1(conn, reader, "http", req.URL.Host, capture, pid)
}

// handleConnect устанавливает HTTPS-туннель и запускает MITM (или сквозной туннель).
func (p *Proxy) handleConnect(client net.Conn, host string, capture bool, pid int) {
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if !capture {
		upstream, err := net.Dial("tcp", host)
		if err != nil {
			return
		}
		defer upstream.Close()
		tunnel(client, upstream)
		return
	}
	tlsConn := tlsx.Server(client, p.ca.GetCertificate)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()
	p.serveTLS(tlsConn, host, capture, pid)
}

// HandleTransparent обслуживает соединение из прозрачного режима, где известен
// исходный адрес назначения (origDst = host:port). Клиент общается напрямую,
// без CONNECT. Мы сами определяем: TLS это или открытый HTTP.
func (p *Proxy) HandleTransparent(conn net.Conn, origDst string, pid int) {
	defer conn.Close()
	capture := p.matches(pid)

	br := bufio.NewReaderSize(conn, 16384)
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	wrapped := &bufConn{Conn: conn, r: br}

	if head[0] == 0x16 { // TLS record: Handshake
		sni := peekSNI(br)

		// MITM только если запрошен И этот хост ранее не отвергал наш сертификат.
		mitm := p.tlsMITM
		if mitm && sni != "" {
			if _, bad := p.mitmFailed.Load(sni); bad {
				mitm = false
			}
		}

		if !mitm {
			// Проброс: вытащить SNI и прозрачно передать трафик, не ломая
			// соединение (клиент может не доверять нашему CA — Flutter/Dart).
			if capture {
				p.emit(render.TLSPassthrough(p.nextID(), pid, sni, origDst))
			}
			upstream, err := net.Dial("tcp", origDst)
			if err != nil {
				return
			}
			defer upstream.Close()
			tunnel(wrapped, upstream)
			return
		}

		// MITM (для приложений, доверяющих нашему CA).
		tlsConn := tlsx.Server(wrapped, p.ca.GetCertificate)
		if err := tlsConn.Handshake(); err != nil {
			// Приложение отвергло наш сертификат: показать причину и запомнить
			// хост, чтобы дальше не рвать соединения, а пробрасывать их.
			if sni != "" {
				p.mitmFailed.Store(sni, struct{}{})
			}
			if capture {
				host := sni
				if host == "" {
					host = origDst
				}
				p.emit(render.MITMRejected(pid, host, err))
			}
			return
		}
		host := tlsConn.ConnectionState().ServerName
		if host == "" {
			host = hostOnly(origDst)
		}
		p.serveTLS(tlsConn, joinDefaultPort(host, origDst), capture, pid)
		return
	}

	// Открытый HTTP: хост берём из заголовка Host, порт — из origDst.
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	req.URL.Scheme = "http"
	if req.URL.Host == "" {
		if req.Host != "" {
			req.URL.Host = req.Host
		} else {
			req.URL.Host = origDst
		}
	}
	if !p.roundtripH1(wrapped, req, "http", req.URL.Host, capture, pid) {
		return
	}
	p.serveH1(wrapped, br, "http", req.URL.Host, capture, pid)
}

// serveTLS обслуживает уже установленное TLS-соединение: HTTP/2 или HTTP/1.x.
func (p *Proxy) serveTLS(tlsConn *tls.Conn, host string, capture bool, pid int) {
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		p.h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: p.h2Handler("https", host, capture, pid),
		})
		return
	}
	p.serveH1(tlsConn, bufio.NewReader(tlsConn), "https", host, capture, pid)
}

// serveH1 обслуживает поток HTTP/1.x-запросов (keep-alive) на одном соединении.
func (p *Proxy) serveH1(client net.Conn, reader *bufio.Reader, scheme, host string, capture bool, pid int) {
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if !p.roundtripH1(client, req, scheme, host, capture, pid) {
			return
		}
	}
}

// roundtripH1 обрабатывает один HTTP/1.x запрос-ответ и пишет ответ клиенту.
func (p *Proxy) roundtripH1(client net.Conn, req *http.Request, scheme, host string, capture bool, pid int) bool {
	resp, respBody, ok := p.process(req, scheme, host, capture, pid)
	if !ok {
		writeGatewayError(client)
		return false
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	stripHopHeaders(resp.Header)
	if err := resp.Write(client); err != nil {
		return false
	}
	return !req.Close && !resp.Close
}

// h2Handler — обработчик HTTP/2 (клиентская сторона), форвардит через общий core.
func (p *Proxy) h2Handler(scheme, host string, capture bool, pid int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.forward(w, r, scheme, host, capture, pid)
	}
}

// forward форвардит запрос через общий core и пишет ответ клиенту (HTTP/2, HTTP/3).
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, scheme, host string, capture bool, pid int) {
	resp, respBody, ok := p.process(r, scheme, host, capture, pid)
	if !ok {
		http.Error(w, "httpsniff upstream error", http.StatusBadGateway)
		return
	}
	dst := w.Header()
	for k, vals := range resp.Header {
		if isHopHeader(k) {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// process — общее ядро: читает тело запроса, форвардит на сервер, читает ответ,
// логирует и возвращает ответ вместе с буферизованным телом.
func (p *Proxy) process(in *http.Request, scheme, host string, capture bool, pid int) (*http.Response, []byte, bool) {
	var reqBody []byte
	if in.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(in.Body, 64<<20))
		in.Body.Close()
	}

	out := in.Clone(context.Background())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = scheme
	}
	if out.URL.Host == "" {
		if host != "" {
			out.URL.Host = host
		} else {
			out.URL.Host = in.Host
		}
	}
	out.Body = io.NopCloser(bytes.NewReader(reqBody))
	out.ContentLength = int64(len(reqBody))
	stripHopHeaders(out.Header)

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		if capture {
			p.emit(render.RequestError(pid, out, err))
		}
		return nil, nil, false
	}

	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
	}
	if capture {
		p.emit(render.Exchange(p.nextID(), pid, out, reqBody, resp, respBody, p.maxBody))
	}
	return resp, respBody, true
}

// clientPID определяет PID процесса, которому принадлежит клиентское соединение.
func (p *Proxy) clientPID(conn net.Conn) int {
	host, portStr, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return -1
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return -1
	}
	pid, err := procinfo.LookupPID(net.ParseIP(host), port)
	if err != nil {
		return -1
	}
	return pid
}

// emit выводит блок лога в приёмник и (если задан) в файл без ANSI-кодов.
func (p *Proxy) emit(block string) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if p.logger != nil {
		p.logger.Log(block)
	} else {
		os.Stdout.WriteString(block)
	}
	if p.logFile != nil {
		io.WriteString(p.logFile, render.StripANSI(block))
	}
}

func (p *Proxy) nextID() uint64 { return p.counter.Add(1) }

// peekSNI без потребления байт извлекает SNI из ClientHello.
func peekSNI(br *bufio.Reader) string {
	h5, err := br.Peek(5)
	if err != nil || h5[0] != 0x16 {
		return ""
	}
	recLen := int(h5[3])<<8 | int(h5[4])
	full, err := br.Peek(5 + recLen)
	if err != nil {
		full, _ = br.Peek(br.Buffered())
	}
	host, _ := tlsx.ParseClientHelloSNI(full)
	return host
}

// tunnel двунаправленно копирует данные между двумя соединениями.
func tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

func writeGatewayError(w io.Writer) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("httpsniff upstream error")),
	}
	resp.Write(w)
}

// bufConn — net.Conn, у которого Read идёт через буфер (для «подсмотренных» байт).
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

var hopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isHopHeader(k string) bool { return hopHeaders[strings.ToLower(k)] }

func stripHopHeaders(h http.Header) {
	for k := range h {
		if isHopHeader(k) {
			h.Del(k)
		}
	}
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// joinDefaultPort возвращает host:port, беря порт из origDst (или 443).
func joinDefaultPort(host, origDst string) string {
	if _, port, err := net.SplitHostPort(host); err == nil && port != "" {
		return host
	}
	port := "443"
	if _, port2, err := net.SplitHostPort(origDst); err == nil && port2 != "" {
		port = port2
	}
	return net.JoinHostPort(host, port)
}

// fileExists используется платформенным кодом прозрачного режима.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
