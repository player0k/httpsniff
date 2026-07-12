//go:build windows

package procinfo

import (
	"syscall"
	"unsafe"
)

var (
	kernel32t                = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snap = kernel32t.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = kernel32t.NewProc("Process32FirstW")
	procProcess32NextW       = kernel32t.NewProc("Process32NextW")
	procCloseHandleT         = kernel32t.NewProc("CloseHandle")
)

const th32csSnapProcess = 0x00000002

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// ParentMap возвращает отображение PID -> PPID для всех процессов системы.
func ParentMap() map[int]int {
	res := make(map[int]int)
	snap, _, _ := procCreateToolhelp32Snap.Call(uintptr(th32csSnapProcess), 0)
	if snap == 0 || snap == uintptr(^uintptr(0)) { // INVALID_HANDLE_VALUE
		return res
	}
	defer procCloseHandleT.Call(snap)

	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for r != 0 {
		res[int(pe.ProcessID)] = int(pe.ParentProcessID)
		r, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return res
}
