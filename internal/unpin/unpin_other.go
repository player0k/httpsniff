//go:build !windows

package unpin

import (
	"fmt"
	"os"
)

// Result — итог попытки unpin (на не-Windows всегда Skipped/недоступен).
type Result struct {
	Applied   bool
	AlreadyOK bool
	Skipped   bool
	Message   string
	Err       error
}

// Supported сообщает, доступен ли unpin на этой платформе.
func Supported() bool { return false }

// Run — заглушка: обход TLS Flutter доступен только в Windows.
func Run(args []string) {
	fmt.Fprintln(os.Stderr, "Подкоманда unpin (обход TLS Flutter) доступна только в Windows.")
	os.Exit(2)
}

// Apply — заглушка: на не-Windows unpin недоступен.
func Apply(pid int) Result {
	return Result{
		Skipped: true,
		Message: "unpin is only available on Windows",
	}
}

// Watcher — заглушка для API-совместимости.
type Watcher struct{}

// StartWatcher на не-Windows возвращает no-op watcher.
func StartWatcher(log func(string), onPatched func(pid int)) *Watcher {
	return &Watcher{}
}

// TryPID — заглушка.
func (w *Watcher) TryPID(pid int) Result {
	return Apply(pid)
}

// Stop — no-op.
func (w *Watcher) Stop() {}
