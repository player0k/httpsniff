//go:build windows

package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"httpsniff/internal/procinfo"
)

// winDivertRedirector перенаправляет исходящий TCP-трафик выбранных процессов
// (по PID/дереву) на локальный порт перехватчика через драйвер WinDivert.
//
// Приём (проверенная схема «dst=src»): исходящий пакет к server:443 переписываем
// так, чтобы он ушёл на наш адрес (dst=собственный IP, порт = tport). Ответы прокси
// (srcPort==tport) переписываем обратно на server:443, чтобы приложение ничего не
// заметило. Исходный адрес назначения запоминаем по порту источника клиента.
type winDivertRedirector struct {
	open, recv, send, closeP, calc, shutdown *syscall.LazyProc
	handle                                   uintptr
	tport                                    uint16
	ourPID                                   int
	match                                    func(pid int) bool

	mu    sync.Mutex
	conns map[uint16]origDstEntry
	skip  map[uint16]bool
	stop  int32
}

type origDstEntry struct {
	ip   [4]byte
	port uint16
}

const (
	winDivertLayerNetwork = 0
	winDivertShutdownBoth = 3
	invalidHandle         = ^uintptr(0)
)

func newWinDivertRedirector(dllPath string, tport, ourPID int, match func(int) bool) (*winDivertRedirector, error) {
	dll := syscall.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("не удалось загрузить WinDivert.dll: %w", err)
	}
	r := &winDivertRedirector{
		open:     dll.NewProc("WinDivertOpen"),
		recv:     dll.NewProc("WinDivertRecv"),
		send:     dll.NewProc("WinDivertSend"),
		closeP:   dll.NewProc("WinDivertClose"),
		calc:     dll.NewProc("WinDivertHelperCalcChecksums"),
		shutdown: dll.NewProc("WinDivertShutdown"),
		tport:    uint16(tport),
		ourPID:   ourPID,
		match:    match,
		conns:    make(map[uint16]origDstEntry),
		skip:     make(map[uint16]bool),
	}
	return r, nil
}

func (r *winDivertRedirector) start() error {
	filter := fmt.Sprintf("outbound and ip and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == %d)", r.tport)
	fp, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return err
	}
	h, _, e := r.open.Call(uintptr(unsafe.Pointer(fp)), uintptr(winDivertLayerNetwork), 0, 0)
	if h == invalidHandle {
		return fmt.Errorf("WinDivertOpen не удался (нужны админ и WinDivert64.sys): %v", e)
	}
	r.handle = h
	go r.loop()
	return nil
}

func (r *winDivertRedirector) loop() {
	packet := make([]byte, 65535)
	addr := make([]byte, 80) // WINDIVERT_ADDRESS
	for atomic.LoadInt32(&r.stop) == 0 {
		var recvLen uint32
		ok, _, _ := r.recv.Call(
			r.handle,
			uintptr(unsafe.Pointer(&packet[0])),
			uintptr(len(packet)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ok == 0 {
			if atomic.LoadInt32(&r.stop) != 0 {
				return
			}
			continue
		}
		n := int(recvLen)
		modified := r.process(packet[:n], addr)
		if modified {
			r.calc.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(n), uintptr(unsafe.Pointer(&addr[0])), 0)
		}
		var sendLen uint32
		r.send.Call(
			r.handle,
			uintptr(unsafe.Pointer(&packet[0])),
			uintptr(recvLen),
			uintptr(unsafe.Pointer(&sendLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
	}
}

// process модифицирует пакет на месте; возвращает true, если нужно пересчитать
// контрольные суммы.
func (r *winDivertRedirector) process(p, addr []byte) bool {
	if len(p) < 20 || p[0]>>4 != 4 { // только IPv4
		return false
	}
	ihl := int(p[0]&0x0f) * 4
	if p[9] != 6 || len(p) < ihl+20 { // только TCP
		return false
	}
	srcIP := p[12:16]
	dstIP := p[16:20]
	tcp := p[ihl:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	flags := tcp[13]
	isSyn := flags&0x02 != 0 && flags&0x10 == 0
	isFinRst := flags&0x01 != 0 || flags&0x04 != 0

	// Ответ прокси приложению: восстановить исходный адрес сервера.
	if srcPort == r.tport {
		if od, ok := r.getConn(dstPort); ok {
			copy(srcIP, od.ip[:])
			binary.BigEndian.PutUint16(tcp[0:2], od.port)
			if isFinRst {
				r.delConn(dstPort)
			}
			return true
		}
		return false
	}

	if dstPort != 80 && dstPort != 443 {
		return false
	}
	cport := srcPort

	// Уже отслеживаемое соединение — перенаправляем на наш порт.
	if _, ok := r.getConn(cport); ok {
		copy(dstIP, srcIP) // dst = собственный IP машины
		binary.BigEndian.PutUint16(tcp[2:4], r.tport)
		return true
	}
	if r.isSkip(cport) {
		return false
	}
	if !isSyn {
		return false
	}
	// Новое соединение: решаем по PID процесса-владельца порта.
	pid, err := procinfo.LookupPID(nil, int(cport))
	if err != nil || pid == r.ourPID || !r.match(pid) {
		r.setSkip(cport)
		return false
	}
	var e origDstEntry
	copy(e.ip[:], dstIP)
	e.port = dstPort
	r.setConn(cport, e)
	copy(dstIP, srcIP)
	binary.BigEndian.PutUint16(tcp[2:4], r.tport)
	return true
}

// OrigDst возвращает исходный адрес назначения по порту клиента.
func (r *winDivertRedirector) OrigDst(cport uint16) (string, bool) {
	od, ok := r.getConn(cport)
	if !ok {
		return "", false
	}
	ip := net.IPv4(od.ip[0], od.ip[1], od.ip[2], od.ip[3])
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(od.port))), true
}

func (r *winDivertRedirector) stopRedirect() {
	atomic.StoreInt32(&r.stop, 1)
	if r.handle != 0 && r.handle != invalidHandle {
		r.shutdown.Call(r.handle, uintptr(winDivertShutdownBoth))
		r.closeP.Call(r.handle)
	}
}

func (r *winDivertRedirector) getConn(port uint16) (origDstEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.conns[port]
	return e, ok
}
func (r *winDivertRedirector) setConn(port uint16, e origDstEntry) {
	r.mu.Lock()
	r.conns[port] = e
	r.mu.Unlock()
}
func (r *winDivertRedirector) delConn(port uint16) {
	r.mu.Lock()
	delete(r.conns, port)
	r.mu.Unlock()
}
func (r *winDivertRedirector) isSkip(port uint16) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.skip[port]
}
func (r *winDivertRedirector) setSkip(port uint16) {
	r.mu.Lock()
	r.skip[port] = true
	r.mu.Unlock()
}
