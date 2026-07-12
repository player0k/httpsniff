//go:build !windows && !linux && !darwin

package sysproxy

import (
	"errors"

	"httpsniff/internal/i18n"
)

// Enable — заглушка: автонастройка системного прокси на этой платформе не поддержана.
func Enable(hostPort string) (func(), error) {
	return nil, errors.New(i18n.T("sysproxy.errUnsupported"))
}

// Recover — заглушка (нечего восстанавливать).
func Recover() {}

// Hint — заглушка (нет платформенной подсказки).
func Hint() string { return "" }
