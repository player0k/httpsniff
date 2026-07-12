//go:build windows

// Package procinfo определяет PID процесса-владельца TCP-порта и строит дерево
// процессов (PID -> PPID) для матча по всему поддереву.
package procinfo

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPidAll = 5
	afInet              = 2
	afInet6             = 23
)

// LookupPID возвращает PID процесса, владеющего локальным TCP-портом.
// Клиент подключается к нашему прокси со своего эфемерного порта — по нему
// и находим владельца в таблице TCP-соединений системы.
func LookupPID(localIP net.IP, localPort int) (int, error) {
	if pid, ok := findPID(afInet, localPort); ok {
		return pid, nil
	}
	if pid, ok := findPID(afInet6, localPort); ok {
		return pid, nil
	}
	return 0, fmt.Errorf("процесс для порта %d не найден", localPort)
}

func findPID(family uint32, port int) (int, bool) {
	var size uint32
	// Первый вызов — узнаём необходимый размер буфера.
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(tcpTableOwnerPidAll),
		0,
	)
	if size == 0 {
		return 0, false
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(tcpTableOwnerPidAll),
		0,
	)
	if ret != 0 {
		return 0, false
	}

	n := binary.LittleEndian.Uint32(buf[0:4])

	if family == afInet {
		const rowSize = 24 // MIB_TCPROW_OWNER_PID
		for i := uint32(0); i < n; i++ {
			off := 4 + int(i)*rowSize
			if off+rowSize > len(buf) {
				break
			}
			row := buf[off : off+rowSize]
			// state[0:4] localAddr[4:8] localPort[8:12] ... owningPid[20:24]
			lport := int(row[8])<<8 | int(row[9]) // порт в сетевом порядке байт
			if lport == port {
				return int(binary.LittleEndian.Uint32(row[20:24])), true
			}
		}
		return 0, false
	}

	const rowSize = 56 // MIB_TCP6ROW_OWNER_PID
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		// localAddr[0:16] localScopeId[16:20] localPort[20:24] ... owningPid[52:56]
		lport := int(row[20])<<8 | int(row[21])
		if lport == port {
			return int(binary.LittleEndian.Uint32(row[52:56])), true
		}
	}
	return 0, false
}
