//go:build windows

// Package sysproxy включает и восстанавливает системные настройки прокси
// (перехват «из коробки»), с восстановлением даже после аварийного завершения.
package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"httpsniff/internal/i18n"
)

const inetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

// savedProxy — снимок прежних настроек прокси для восстановления (в т.ч. после сбоя).
type savedProxy struct {
	Enable       uint32 `json:"enable"`
	EnableExists bool   `json:"enable_exists"`
	Server       string `json:"server"`
	ServerExists bool   `json:"server_exists"`
}

func stateFilePath() string {
	return filepath.Join(os.TempDir(), "httpsniff-sysproxy.json")
}

// Enable включает системный прокси Windows (WinINET) на наш адрес.
// Возвращает функцию восстановления прежних настроек.
func Enable(hostPort string) (func(), error) {
	// Сначала лечим последствия возможного прошлого аварийного завершения.
	recoverStale()

	key, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("открытие ключа Internet Settings: %w", err)
	}
	defer key.Close()

	var snap savedProxy
	if v, _, err := key.GetIntegerValue("ProxyEnable"); err == nil {
		snap.Enable, snap.EnableExists = uint32(v), true
	}
	if v, _, err := key.GetStringValue("ProxyServer"); err == nil {
		snap.Server, snap.ServerExists = v, true
	}
	// Сохраняем снимок на диск — чтобы восстановиться даже после kill/сбоя.
	if data, err := json.Marshal(snap); err == nil {
		os.WriteFile(stateFilePath(), data, 0600)
	}

	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return nil, fmt.Errorf("установка ProxyEnable: %w", err)
	}
	if err := key.SetStringValue("ProxyServer", hostPort); err != nil {
		return nil, fmt.Errorf("установка ProxyServer: %w", err)
	}
	_ = key.SetStringValue("ProxyOverride", "<local>")
	notifyWinInet()

	restore := func() {
		applyProxy(snap)
		os.Remove(stateFilePath())
	}
	return restore, nil
}

// recoverStale восстанавливает настройки из файла-состояния, оставшегося от
// прошлого аварийно завершённого запуска.
func recoverStale() {
	data, err := os.ReadFile(stateFilePath())
	if err != nil {
		return
	}
	var snap savedProxy
	if json.Unmarshal(data, &snap) == nil {
		applyProxy(snap)
	}
	os.Remove(stateFilePath())
}

func applyProxy(snap savedProxy) {
	key, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	if snap.EnableExists {
		key.SetDWordValue("ProxyEnable", snap.Enable)
	} else {
		key.SetDWordValue("ProxyEnable", 0)
	}
	if snap.ServerExists {
		key.SetStringValue("ProxyServer", snap.Server)
	} else {
		key.SetStringValue("ProxyServer", "")
	}
	notifyWinInet()
}

// notifyWinInet уведомляет систему об изменении настроек прокси, чтобы
// приложения (браузеры и всё, что использует WinINET) сразу их подхватили.
func notifyWinInet() {
	procInternetSetOptionW.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	procInternetSetOptionW.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

// Recover восстанавливает настройки прокси из файла-состояния (например, после
// аварийного завершения прошлого запуска).
func Recover() { recoverStale() }

// Hint возвращает подсказку о поведении системного прокси на этой платформе.
func Hint() string { return i18n.T("sysproxy.hintWin") }
