//go:build windows

// Package winconfig управляет loopback-исключениями AppContainer (аналог кнопки
// WinConfig в Fiddler) через API сетевой изоляции Windows.
package winconfig

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"httpsniff/internal/i18n"
)

// ── WinConfig: управление loopback-исключениями AppContainer ──────────────
//
// Windows 11 изолирует UWP/WinUI/Store-приложения в AppContainer, из-за чего
// они не могут обращаться к локальному (loopback) прокси. Fiddler решает это
// кнопкой WinConfig, вызывая тот же API сетевой изоляции. Здесь — его аналог.
//
// Используемые функции FirewallAPI.dll:
//   NetworkIsolationEnumAppContainers   — перечислить все AppContainer
//   NetworkIsolationGetAppContainerConfig — текущий список исключений loopback
//   NetworkIsolationSetAppContainerConfig — задать список исключений loopback
//   NetworkIsolationFreeAppContainers   — освободить буфер перечисления

var (
	firewallAPI = syscall.NewLazyDLL("FirewallAPI.dll")
	advapi32    = syscall.NewLazyDLL("advapi32.dll")
	shell32     = syscall.NewLazyDLL("shell32.dll")
	kernel32w   = syscall.NewLazyDLL("kernel32.dll")

	procEnumAppContainers = firewallAPI.NewProc("NetworkIsolationEnumAppContainers")
	procGetACConfig       = firewallAPI.NewProc("NetworkIsolationGetAppContainerConfig")
	procSetACConfig       = firewallAPI.NewProc("NetworkIsolationSetAppContainerConfig")
	procFreeACs           = firewallAPI.NewProc("NetworkIsolationFreeAppContainers")

	procConvertSidToStr = advapi32.NewProc("ConvertSidToStringSidW")
	procIsUserAnAdmin   = shell32.NewProc("IsUserAnAdmin")
	procLocalFree       = kernel32w.NewProc("LocalFree")
)

// SID_AND_ATTRIBUTES (Sid как uintptr, чтобы не нарушать проверку cgo:
// массив не содержит Go-указателей и его можно передавать в WinAPI).
type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
	_          uint32 // выравнивание до 16 байт на amd64
}

// Раскладка INET_FIREWALL_APP_CONTAINER (amd64), нужны только SID и имена.
type inetFirewallACCapabilities struct {
	count        uint32
	_            uint32
	capabilities uintptr
}
type inetFirewallACBinaries struct {
	count    uint32
	_        uint32
	binaries uintptr
}
type inetFirewallAppContainer struct {
	appContainerSid  uintptr // PSID — в Go не разыменовываем, передаём как есть
	userSid          uintptr
	appContainerName unsafe.Pointer // PWSTR
	displayName      unsafe.Pointer
	description      unsafe.Pointer
	capabilities     inetFirewallACCapabilities
	binaries         inetFirewallACBinaries
	workingDirectory unsafe.Pointer
	packageFullName  unsafe.Pointer
}

type appContainer struct {
	sidPtr  uintptr // указатель в нативный буфер перечисления
	sidStr  string
	name    string
	display string
	pkg     string
}

// Run исполняет подкоманду winconfig (list/exempt-all/exempt/clear).
func Run(args []string) {
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}

	switch cmd {
	case "list":
		winConfigList()
	case "exempt-all":
		winConfigExemptAll()
	case "exempt":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, i18n.T("wc.needSubstr"))
			os.Exit(2)
		}
		winConfigExempt(strings.Join(args[1:], " "))
	case "clear":
		winConfigClear()
	default:
		fmt.Fprint(os.Stderr, i18n.T("wc.usage"))
		os.Exit(2)
	}
}

// enumAppContainers перечисляет все AppContainer. Возвращает список и функцию
// освобождения нативного буфера — вызывать её нужно ПОСЛЕ Set, т.к. sidPtr
// указывают внутрь этого буфера.
func enumAppContainers() ([]appContainer, func(), error) {
	var count uint32
	var ptr unsafe.Pointer
	r, _, _ := procEnumAppContainers.Call(
		0, // flags
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&ptr)),
	)
	if r != 0 {
		return nil, func() {}, errors.New(i18n.T("wc.enumErr", r))
	}

	free := func() { procFreeACs.Call(uintptr(ptr)) }

	size := unsafe.Sizeof(inetFirewallAppContainer{})
	base := ptr
	list := make([]appContainer, 0, count)
	for i := uint32(0); i < count; i++ {
		ac := (*inetFirewallAppContainer)(unsafe.Add(base, uintptr(i)*size))
		list = append(list, appContainer{
			sidPtr:  ac.appContainerSid,
			sidStr:  sidToString(ac.appContainerSid),
			name:    lpwstrToString(ac.appContainerName),
			display: lpwstrToString(ac.displayName),
			pkg:     lpwstrToString(ac.packageFullName),
		})
	}
	return list, free, nil
}

// currentExemptions возвращает множество SID-строк, уже имеющих loopback-исключение.
func currentExemptions() map[string]bool {
	var num uint32
	var arr unsafe.Pointer
	set := make(map[string]bool)
	r, _, _ := procGetACConfig.Call(
		uintptr(unsafe.Pointer(&num)),
		uintptr(unsafe.Pointer(&arr)),
	)
	if r != 0 || arr == nil {
		return set
	}
	elemSize := unsafe.Sizeof(sidAndAttributes{})
	base := arr
	for i := uint32(0); i < num; i++ {
		e := (*sidAndAttributes)(unsafe.Add(base, uintptr(i)*elemSize))
		set[sidToString(e.Sid)] = true
	}
	return set
}

func winConfigList() {
	list, free, err := enumAppContainers()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("wc.error"), err)
		os.Exit(1)
	}
	defer free()

	exempt := currentExemptions()
	fmt.Printf("%s\n\n", i18n.T("wc.found", len(list)))
	for _, ac := range list {
		mark := " "
		if exempt[ac.sidStr] {
			mark = "\033[1;32m✓\033[0m"
		}
		label := ac.display
		if label == "" {
			label = ac.name
		}
		fmt.Printf("[%s] %s\n     %s\n", mark, label, ac.pkg)
	}
	fmt.Printf("\n%s\n", i18n.T("wc.exemptCount", len(exempt)))
}

func winConfigExemptAll() {
	requireAdmin()
	list, free, err := enumAppContainers()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("wc.error"), err)
		os.Exit(1)
	}
	defer free()

	sids := make([]sidAndAttributes, 0, len(list))
	for _, ac := range list {
		if ac.sidPtr != 0 {
			sids = append(sids, sidAndAttributes{Sid: ac.sidPtr})
		}
	}
	setConfig(sids)
	fmt.Printf("\033[1;32m%s\033[0m\n", i18n.T("wc.exemptAllDone", len(sids)))
}

func winConfigExempt(substr string) {
	requireAdmin()
	list, free, err := enumAppContainers()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("wc.error"), err)
		os.Exit(1)
	}
	defer free()

	// Сохраняем уже существующие исключения и добавляем совпавшие.
	existing := currentExemptions()
	sids := make([]sidAndAttributes, 0)
	seen := make(map[string]bool)

	// текущие исключения переносим, находя их SID среди перечисленных
	for _, ac := range list {
		if existing[ac.sidStr] && ac.sidPtr != 0 && !seen[ac.sidStr] {
			sids = append(sids, sidAndAttributes{Sid: ac.sidPtr})
			seen[ac.sidStr] = true
		}
	}

	needle := strings.ToLower(substr)
	matched := 0
	for _, ac := range list {
		hay := strings.ToLower(ac.display + " " + ac.name + " " + ac.pkg)
		if strings.Contains(hay, needle) && ac.sidPtr != 0 && !seen[ac.sidStr] {
			sids = append(sids, sidAndAttributes{Sid: ac.sidPtr})
			seen[ac.sidStr] = true
			matched++
			label := ac.display
			if label == "" {
				label = ac.name
			}
			fmt.Printf("  + %s\n", label)
		}
	}
	if matched == 0 {
		fmt.Println(i18n.T("wc.noMatch", substr))
		return
	}
	setConfig(sids)
	fmt.Printf("\033[1;32m%s\033[0m\n", i18n.T("wc.exemptDone", matched, len(sids)))
}

func winConfigClear() {
	requireAdmin()
	// Пустой список снимает все исключения.
	r, _, _ := procSetACConfig.Call(0, 0)
	if r != 0 {
		fmt.Fprintln(os.Stderr, i18n.T("wc.setErr", r))
		os.Exit(1)
	}
	fmt.Println(i18n.T("wc.cleared"))
}

func setConfig(sids []sidAndAttributes) {
	var p uintptr
	if len(sids) > 0 {
		p = uintptr(unsafe.Pointer(&sids[0]))
	}
	r, _, _ := procSetACConfig.Call(uintptr(len(sids)), p)
	if r != 0 {
		fmt.Fprint(os.Stderr, i18n.T("wc.setErr", r))
		if r == 5 {
			fmt.Fprintln(os.Stderr, i18n.T("wc.setErrDenied"))
		} else {
			fmt.Fprintln(os.Stderr, "")
		}
		os.Exit(1)
	}
}

func requireAdmin() {
	r, _, _ := procIsUserAnAdmin.Call()
	if r == 0 {
		fmt.Fprintf(os.Stderr, "\033[1;33m%s\033[0m\n", i18n.T("wc.needAdmin"))
	}
}

// ── вспомогательные ──

func sidToString(psid uintptr) string {
	if psid == 0 {
		return ""
	}
	var strPtr unsafe.Pointer
	r, _, _ := procConvertSidToStr.Call(psid, uintptr(unsafe.Pointer(&strPtr)))
	if r == 0 || strPtr == nil {
		return ""
	}
	s := lpwstrToString(strPtr)
	procLocalFree.Call(uintptr(strPtr))
	return s
}

func lpwstrToString(base unsafe.Pointer) string {
	if base == nil {
		return ""
	}
	var buf []uint16
	for i := uintptr(0); ; i++ {
		c := *(*uint16)(unsafe.Add(base, i*2))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return string(utf16.Decode(buf))
}
