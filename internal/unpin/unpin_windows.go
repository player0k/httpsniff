//go:build windows

// Package unpin отключает проверку TLS у Flutter-приложений (Dart/BoringSSL) на
// Windows патчем памяти, чтобы MITM с нашим CA перестал ломаться.
package unpin

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"httpsniff/internal/i18n"
)

// Отключение проверки TLS у Flutter-приложений (Dart/BoringSSL) на Windows.
//
// Flutter использует собственные корневые сертификаты, поэтому наш CA ему не
// доверен и MITM ломается. Приём (как в Frida-скриптах Anof-cyber / NVISO):
// найти в flutter_windows.dll функцию проверки цепочки сертификата
// (ssl_crypto_x509_session_verify_cert_chain) по прологу и заставить её всегда
// возвращать успех (1), заменив на `mov eax,1; ret`.
//
// Требуются права администратора (запись в память чужого процесса).

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procCreateToolhelp32Snap = kernel32.NewProc("CreateToolhelp32Snapshot")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
	procModule32FirstW       = kernel32.NewProc("Module32FirstW")
	procModule32NextW        = kernel32.NewProc("Module32NextW")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
	procReadProcessMemory    = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMem      = kernel32.NewProc("WriteProcessMemory")
	procVirtualProtectEx     = kernel32.NewProc("VirtualProtectEx")
	procFlushInstrCache      = kernel32.NewProc("FlushInstructionCache")
	procIsUserAnAdmin        = shell32.NewProc("IsUserAnAdmin")
)

const (
	invalidHandle = ^uintptr(0)

	th32csSnapModule   = 0x00000008
	th32csSnapModule32 = 0x00000010

	processVMRead    = 0x0010
	processVMWrite   = 0x0020
	processVMOp      = 0x0008
	processQueryInfo = 0x0400

	pageExecReadWrite = 0x40
)

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

// Пролог ssl_crypto_x509_session_verify_cert_chain в flutter_windows.dll (x64).
// Хвост `48 8B 05 ?? ?? ?? ??` (mov rax,[rip+off]) — со смещением, зависящим от
// сборки, поэтому оно замаскировано.
const defaultSig = "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 48 89 CF 48 8B 05 ?? ?? ?? ??"

// sigEntry — элемент реестра известных сигнатур для разных версий Flutter/BoringSSL.
type sigEntry struct {
	name string
	sig  string
	desc string
}

// knownSigs — реестр известных сигнатур для разных версий Flutter/BoringSSL.
// Каждая сигнатура содержит: имя, hex-паттерн и описание версии.
var knownSigs = []sigEntry{
	{
		name: "flutter-3.x",
		sig:  defaultSig,
		desc: "Flutter 3.x (BoringSSL) — стандартная сигнатура",
	},
	{
		name: "flutter-3.16+",
		sig:  "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 30 48 89 CF 48 8B 05 ?? ?? ?? ??",
		desc: "Flutter 3.16+ (новый BoringSSL)",
	},
	{
		name: "flutter-3.19+",
		sig:  "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 48 89 CE 48 8B 05 ?? ?? ?? ??",
		desc: "Flutter 3.19+ (обновлённый пролог)",
	},
	{
		name: "flutter-3.22+",
		sig:  "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 50 48 89 CF 48 8B 05 ?? ?? ?? ??",
		desc: "Flutter 3.22+ (расширенный стек)",
	},
}

// patchBytes — патч: mov eax,1; ret => функция всегда возвращает 1 (успех проверки).
// ssl_crypto_x509_session_verify_cert_chain возвращает bool: 1 = проверка пройдена,
// 0 = провал. Поэтому для обхода нужен именно возврат 1 (а не 0).
var patchBytes = []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}

// altSig — пролог функции, УЖЕ ошибочно пропатченной ранней версией
// (`31 C0 C3` = xor eax,eax; ret вместо байтов `41 57 41`), чтобы можно было
// исправить такой процесс на возврат 1 без перезапуска приложения.
const altSig = "31 C0 C3 56 41 55 41 54 56 57 53 48 83 EC 40 48 89 CF 48 8B 05 ?? ?? ?? ??"

// Run исполняет подкоманду unpin: поиск (dry-run) или применение патча.
func Run(args []string) {
	fs := flag.NewFlagSet("unpin", flag.ExitOnError)
	pid := fs.Int("pid", 0, i18n.T("up.flagPid"))
	apply := fs.Bool("apply", false, i18n.T("up.flagApply"))
	auto := fs.Bool("auto", false, i18n.T("up.flagAuto"))
	sig := fs.String("sig", defaultSig, i18n.T("up.flagSig"))
	dump := fs.Bool("dump", false, i18n.T("up.flagDump"))
	fs.Parse(args)

	if *pid == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("up.needPid"))
		os.Exit(2)
	}
	if !isAdmin() {
		fmt.Fprintf(os.Stderr, "\033[1;33m%s\033[0m\n", i18n.T("up.needAdmin"))
	}

	base, size, err := findModule(*pid, "flutter_windows.dll")
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("up.moduleErr", *pid, err))
		os.Exit(1)
	}
	fmt.Println(i18n.T("up.moduleInfo", base, size))

	proc, err := openProcess(*pid, *apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("up.openErr", err))
		os.Exit(1)
	}
	defer procCloseHandle.Call(proc)

	mem := readModule(proc, base, size)

	// Автоматический режим: перебираем все известные сигнатуры.
	if *auto {
		runAuto(proc, mem, base, *apply, *dump)
		return
	}

	// Ручной режим: используем указанную сигнатуру.
	pattern, err := parseSig(*sig)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("up.sigErr"), err)
		os.Exit(2)
	}

	runManual(proc, mem, base, pattern, *apply, *dump)
}

// runAuto выполняет автоматический перебор известных сигнатур.
func runAuto(proc uintptr, mem []byte, base uintptr, apply, dump bool) {
	fmt.Println(i18n.T("up.autoStart"))

	// Сначала проверяем, не пропатчен ли уже (altSig).
	if alt, e := parseSig(altSig); e == nil {
		if am := scanAll(mem, alt); len(am) == 1 {
			fmt.Println(i18n.T("up.autoAlreadyPatched"))
			if apply {
				addr := base + uintptr(am[0])
				if dump {
					dumpBytes(proc, addr, "ДО патча")
				}
				if err := patch(proc, addr, patchBytes); err != nil {
					fmt.Fprintln(os.Stderr, i18n.T("up.patchErr", err))
					os.Exit(1)
				}
				if dump {
					dumpBytes(proc, addr, "ПОСЛЕ патча")
				}
				fmt.Printf("\033[1;32m%s\033[0m\n", i18n.T("up.patchOK"))
			} else {
				fmt.Println(i18n.T("up.autoDryRun"))
			}
			return
		}
	}

	// Перебираем все известные сигнатуры.
	for _, entry := range knownSigs {
		pattern, err := parseSig(entry.sig)
		if err != nil {
			continue
		}

		matches := scanAll(mem, pattern)
		if len(matches) == 1 {
			fmt.Printf("\033[1;32m%s\033[0m\n", i18n.T("up.autoFound", entry.name, entry.desc))
			addr := base + uintptr(matches[0])
			fmt.Println(i18n.T("up.funcAddr", addr))

			if dump || apply {
				dumpBytes(proc, addr, "ДО патча")
			}

			if !apply {
				fmt.Printf("\033[2m%s\033[0m\n", i18n.T("up.autoDryRun"))
				return
			}

			if err := patch(proc, addr, patchBytes); err != nil {
				fmt.Fprintln(os.Stderr, i18n.T("up.patchErr", err))
				os.Exit(1)
			}

			if dump {
				dumpBytes(proc, addr, "ПОСЛЕ патча")
			}

			fmt.Printf("\033[1;32m%s\033[0m\n", i18n.T("up.patchOK"))
			return
		}
	}

	// Ни одна сигнатура не подошла.
	fmt.Fprintln(os.Stderr, i18n.T("up.autoNotFound"))
	os.Exit(1)
}

// runManual выполняет ручной поиск с указанной сигнатурой.
func runManual(proc uintptr, mem []byte, base uintptr, pattern []int, apply, dump bool) {
	matches := scanAll(mem, pattern)
	// Если исходный пролог не найден — возможно, процесс уже пропатчен ранней
	// (ошибочной, возврат 0) версией; ищем такой пролог и исправляем его.
	if len(matches) == 0 {
		if alt, e := parseSig(altSig); e == nil {
			if am := scanAll(mem, alt); len(am) == 1 {
				fmt.Println(i18n.T("up.correcting"))
				matches = am
			}
		}
	}
	fmt.Println(i18n.T("up.matches", len(matches)))
	if len(matches) == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("up.notFound"))
		os.Exit(1)
	}
	if len(matches) > 1 {
		fmt.Fprintln(os.Stderr, i18n.T("up.multiple"))
		for _, m := range matches {
			fmt.Fprintf(os.Stderr, "  0x%X\n", base+uintptr(m))
		}
		os.Exit(1)
	}

	addr := base + uintptr(matches[0])
	fmt.Println(i18n.T("up.funcAddr", addr))

	// Показать байты ДО патча (диагностический режим).
	if dump || apply {
		dumpBytes(proc, addr, "ДО патча")
	}

	if !apply {
		fmt.Printf("\033[2m%s\033[0m\n", i18n.T("up.dryRun"))
		return
	}
	if err := patch(proc, addr, patchBytes); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("up.patchErr", err))
		os.Exit(1)
	}

	// Показать байты ПОСЛЕ патча.
	if dump {
		dumpBytes(proc, addr, "ПОСЛЕ патча")
	}

	fmt.Printf("\033[1;32m%s\033[0m\n", i18n.T("up.patchOK"))
}

func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

// dumpBytes читает и показывает первые 32 байта по адресу функции.
func dumpBytes(proc uintptr, addr uintptr, label string) {
	const n = 32
	buf := make([]byte, n)
	var read uintptr
	procReadProcessMemory.Call(proc, addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&read)))
	fmt.Printf("\033[2m  %s (0x%X): ", label, addr)
	for i := 0; i < int(read); i++ {
		fmt.Printf("%02X ", buf[i])
	}
	fmt.Println("\033[0m")
}

func findModule(pid int, name string) (uintptr, uint32, error) {
	snap, _, _ := procCreateToolhelp32Snap.Call(uintptr(th32csSnapModule|th32csSnapModule32), uintptr(pid))
	if snap == 0 || snap == invalidHandle {
		return 0, 0, fmt.Errorf("снапшот модулей не создан (нужен админ?)")
	}
	defer procCloseHandle.Call(snap)

	var me moduleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	r, _, _ := procModule32FirstW.Call(snap, uintptr(unsafe.Pointer(&me)))
	for r != 0 {
		mod := syscall.UTF16ToString(me.Module[:])
		if strings.EqualFold(mod, name) {
			return me.ModBaseAddr, me.ModBaseSize, nil
		}
		r, _, _ = procModule32NextW.Call(snap, uintptr(unsafe.Pointer(&me)))
	}
	return 0, 0, fmt.Errorf("модуль не найден")
}

func openProcess(pid int, write bool) (uintptr, error) {
	access := uintptr(processVMRead | processQueryInfo)
	if write {
		access |= uintptr(processVMWrite | processVMOp)
	}
	h, _, e := procOpenProcess.Call(access, 0, uintptr(pid))
	if h == 0 {
		return 0, e
	}
	return h, nil
}

func readModule(proc, base uintptr, size uint32) []byte {
	buf := make([]byte, size)
	const chunk = 64 * 1024
	for off := uint32(0); off < size; off += chunk {
		n := uint32(chunk)
		if off+n > size {
			n = size - off
		}
		var read uintptr
		procReadProcessMemory.Call(
			proc,
			base+uintptr(off),
			uintptr(unsafe.Pointer(&buf[off])),
			uintptr(n),
			uintptr(unsafe.Pointer(&read)),
		)
	}
	return buf
}

func patch(proc, addr uintptr, data []byte) error {
	var oldProt uint32
	r, _, e := procVirtualProtectEx.Call(proc, addr, uintptr(len(data)), pageExecReadWrite, uintptr(unsafe.Pointer(&oldProt)))
	if r == 0 {
		return fmt.Errorf("VirtualProtectEx: %v", e)
	}
	var written uintptr
	r, _, e = procWriteProcessMem.Call(proc, addr, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written)))
	if r == 0 || int(written) != len(data) {
		return fmt.Errorf("WriteProcessMemory: %v", e)
	}
	var tmp uint32
	procVirtualProtectEx.Call(proc, addr, uintptr(len(data)), uintptr(oldProt), uintptr(unsafe.Pointer(&tmp)))
	procFlushInstrCache.Call(proc, addr, uintptr(len(data)))
	return nil
}

// ---- сигнатуры ----

func parseSig(s string) ([]int, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, fmt.Errorf("пустая сигнатура")
	}
	pat := make([]int, len(fields))
	for i, f := range fields {
		if f == "??" || f == "?" {
			pat[i] = -1
			continue
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("байт %q: %v", f, err)
		}
		pat[i] = int(v)
	}
	return pat, nil
}

func scanAll(mem []byte, pat []int) []int {
	var res []int
	if len(pat) == 0 || len(mem) < len(pat) {
		return res
	}
	end := len(mem) - len(pat)
	for i := 0; i <= end; i++ {
		ok := true
		for j, b := range pat {
			if b >= 0 && int(mem[i+j]) != b {
				ok = false
				break
			}
		}
		if ok {
			res = append(res, i)
		}
	}
	return res
}
