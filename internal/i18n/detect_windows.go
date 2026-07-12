//go:build windows

package i18n

import "syscall"

var procGetUserDefaultUILanguage = syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// detectSystemLang определяет язык интерфейса пользователя Windows через
// GetUserDefaultUILanguage и сопоставляет первичный LANGID коду языка.
func detectSystemLang() string {
	r, _, _ := procGetUserDefaultUILanguage.Call()
	primary := uint16(r) & 0x3ff // PRIMARYLANGID
	switch primary {
	case 0x09: // LANG_ENGLISH
		return "en"
	case 0x19: // LANG_RUSSIAN
		return "ru"
	case 0x0c: // LANG_FRENCH
		return "fr"
	case 0x07: // LANG_GERMAN
		return "de"
	case 0x13: // LANG_DUTCH
		return "nl"
	case 0x0a: // LANG_SPANISH
		return "es"
	case 0x16: // LANG_PORTUGUESE
		return "pt"
	}
	return "en"
}
