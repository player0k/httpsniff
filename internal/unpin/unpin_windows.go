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
	"sync"
	"syscall"
	"time"
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
	procProcess32FirstW      = kernel32.NewProc("Process32FirstW")
	procProcess32NextW       = kernel32.NewProc("Process32NextW")
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
	th32csSnapProcess  = 0x00000002

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

// processEntry32 — PROCESSENTRY32W (поля после szExeFile не нужны).
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

// Result — итог попытки unpin для одного PID.
type Result struct {
	// Applied — патч записан в память процесса.
	Applied bool
	// AlreadyOK — проверка TLS уже отключена (повторный патч не нужен).
	AlreadyOK bool
	// Skipped — не Flutter (нет flutter_windows.dll) или нечего патчить.
	Skipped bool
	// Message — краткое описание для лога.
	Message string
	// Err — системная ошибка (OpenProcess, запись памяти и т.п.).
	Err error
}

// Supported сообщает, доступен ли unpin на этой платформе.
func Supported() bool { return true }

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

// Apply пытается отключить проверку TLS в процессе pid (режим --auto --apply).
// Безопасно вызывать для любого PID: не-Flutter процессы помечаются Skipped.
func Apply(pid int) Result {
	if pid <= 0 {
		return Result{Skipped: true, Message: "invalid pid"}
	}

	base, size, err := findModule(pid, "flutter_windows.dll")
	if err != nil {
		return Result{Skipped: true, Message: fmt.Sprintf("not Flutter (pid %d)", pid)}
	}

	proc, err := openProcess(pid, true)
	if err != nil {
		return Result{Err: err, Message: fmt.Sprintf("OpenProcess(%d): %v", pid, err)}
	}
	defer procCloseHandle.Call(proc)

	mem := readModule(proc, base, size)

	// Уже пропатчено нами (mov eax,1; ret в начале известной функции)?
	if addr, ok := findAlreadyGood(mem, base); ok {
		return Result{
			AlreadyOK: true,
			Message:   fmt.Sprintf("pid %d: TLS verify already disabled @ 0x%X", pid, addr),
		}
	}

	// Исправляем ошибочный старый патч (return 0).
	if alt, e := parseSig(altSig); e == nil {
		if am := scanAll(mem, alt); len(am) == 1 {
			addr := base + uintptr(am[0])
			if err := patch(proc, addr, patchBytes); err != nil {
				return Result{Err: err, Message: fmt.Sprintf("pid %d: patch failed: %v", pid, err)}
			}
			return Result{
				Applied: true,
				Message: fmt.Sprintf("pid %d: corrected old patch → TLS verify disabled", pid),
			}
		}
	}

	for _, entry := range knownSigs {
		pattern, err := parseSig(entry.sig)
		if err != nil {
			continue
		}
		matches := scanAll(mem, pattern)
		if len(matches) != 1 {
			continue
		}
		addr := base + uintptr(matches[0])
		if err := patch(proc, addr, patchBytes); err != nil {
			return Result{Err: err, Message: fmt.Sprintf("pid %d: patch failed: %v", pid, err)}
		}
		return Result{
			Applied: true,
			Message: fmt.Sprintf("pid %d: unpinned (%s) @ 0x%X", pid, entry.name, addr),
		}
	}

	return Result{
		Skipped: true,
		Message: fmt.Sprintf("pid %d: flutter_windows.dll present, but no known signature", pid),
	}
}

// findAlreadyGood ищет уже применённый успешный патч (mov eax,1; ret) на месте
// известных прологов: первые 3 байта заменены, остаток сигнатуры узнаваем.
func findAlreadyGood(mem []byte, base uintptr) (uintptr, bool) {
	// Ищем наш patchBytes, за которым идёт хвост, похожий на flutter-пролог
	// (после ret обычно идут байты исходной функции — но мы перезаписали только 6 байт).
	// Практичный критерий: patchBytes встречается ровно там, где был knownSig
	// (сравниваем байты [6:] с knownSig[6:]).
	for _, entry := range knownSigs {
		pat, err := parseSig(entry.sig)
		if err != nil || len(pat) < len(patchBytes)+4 {
			continue
		}
		// Собираем паттерн: patchBytes + rest of original with wildcards for first 6.
		combined := make([]int, len(pat))
		for i := range pat {
			if i < len(patchBytes) {
				combined[i] = int(patchBytes[i])
			} else {
				combined[i] = pat[i]
			}
		}
		if m := scanAll(mem, combined); len(m) == 1 {
			return base + uintptr(m[0]), true
		}
	}
	return 0, false
}

// Watcher периодически ищет процессы с flutter_windows.dll и применяет unpin.
type Watcher struct {
	log       func(string)
	onPatched func(pid int)
	interval  time.Duration

	mu       sync.Mutex
	patched  map[int]struct{} // успешно / already OK
	backoff  map[int]time.Time // когда снова трогать «не Flutter / ошибка»
	stopCh   chan struct{}
	stopped  sync.Once
}

// StartWatcher запускает фоновый обход процессов.
// log и onPatched могут быть nil. Остановка — через Watcher.Stop.
func StartWatcher(log func(string), onPatched func(pid int)) *Watcher {
	w := &Watcher{
		log:       log,
		onPatched: onPatched,
		interval:  2 * time.Second,
		patched:   make(map[int]struct{}),
		backoff:   make(map[int]time.Time),
		stopCh:    make(chan struct{}),
	}
	if w.log == nil {
		w.log = func(string) {}
	}
	go w.loop()
	return w
}

// Stop останавливает watcher.
func (w *Watcher) Stop() {
	w.stopped.Do(func() { close(w.stopCh) })
}

// TryPID пытается unpin для конкретного PID (например, после MITM-reject).
// Повторно не трогает уже успешно пропатченные PID.
func (w *Watcher) TryPID(pid int) Result {
	if w == nil || pid <= 0 {
		return Apply(pid)
	}
	w.mu.Lock()
	if _, ok := w.patched[pid]; ok {
		w.mu.Unlock()
		return Result{AlreadyOK: true, Message: fmt.Sprintf("pid %d: already unpinned", pid)}
	}
	w.mu.Unlock()

	res := Apply(pid)
	w.remember(pid, res)
	if res.Applied || res.AlreadyOK {
		if w.onPatched != nil && res.Applied {
			w.onPatched(pid)
		}
		if res.Applied {
			w.log(fmt.Sprintf("\033[1;32m✓ auto-unpin: %s\033[0m\n", res.Message))
		}
	}
	return res
}

func (w *Watcher) loop() {
	// Первый проход сразу — подхватить уже запущенные Flutter-приложения.
	w.scanOnce()
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-t.C:
			w.scanOnce()
		}
	}
}

func (w *Watcher) scanOnce() {
	pids, err := listPIDs()
	if err != nil {
		return
	}
	now := time.Now()
	for _, pid := range pids {
		w.mu.Lock()
		if _, ok := w.patched[pid]; ok {
			w.mu.Unlock()
			continue
		}
		if until, ok := w.backoff[pid]; ok && now.Before(until) {
			w.mu.Unlock()
			continue
		}
		w.mu.Unlock()

		// Быстрая проверка: есть ли flutter_windows.dll.
		if _, _, err := findModule(pid, "flutter_windows.dll"); err != nil {
			w.mu.Lock()
			w.backoff[pid] = now.Add(30 * time.Second)
			w.mu.Unlock()
			continue
		}

		res := Apply(pid)
		w.remember(pid, res)
		if res.Applied {
			w.log(fmt.Sprintf("\033[1;32m✓ auto-unpin: %s\033[0m\n", res.Message))
			if w.onPatched != nil {
				w.onPatched(pid)
			}
		} else if res.AlreadyOK {
			// тихо
		} else if res.Err != nil {
			w.log(fmt.Sprintf("\033[1;33m⚠ auto-unpin pid %d: %v\033[0m\n", pid, res.Err))
		}
	}

	// Чистим backoff/patched для умерших процессов.
	w.gc(pids)
}

func (w *Watcher) remember(pid int, res Result) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case res.Applied, res.AlreadyOK:
		w.patched[pid] = struct{}{}
		delete(w.backoff, pid)
	case res.Skipped:
		// dll есть, но сигнатура не найдена — не долбим каждую секунду;
		// или dll нет (уже обработано выше). Повторим через минуту
		// (обновление Flutter / поздняя загрузка).
		w.backoff[pid] = time.Now().Add(60 * time.Second)
	case res.Err != nil:
		w.backoff[pid] = time.Now().Add(15 * time.Second)
	}
}

func (w *Watcher) gc(live []int) {
	alive := make(map[int]struct{}, len(live))
	for _, p := range live {
		alive[p] = struct{}{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for pid := range w.patched {
		if _, ok := alive[pid]; !ok {
			delete(w.patched, pid)
		}
	}
	for pid := range w.backoff {
		if _, ok := alive[pid]; !ok {
			delete(w.backoff, pid)
		}
	}
}

func listPIDs() ([]int, error) {
	snap, _, err := procCreateToolhelp32Snap.Call(uintptr(th32csSnapProcess), 0)
	if snap == 0 || snap == invalidHandle {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(process) failed")
	}
	defer procCloseHandle.Call(snap)

	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	var out []int
	for r != 0 {
		pid := int(pe.ProcessID)
		if pid > 0 {
			out = append(out, pid)
		}
		r, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return out, nil
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
