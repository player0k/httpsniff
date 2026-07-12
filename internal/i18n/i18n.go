// Package i18n реализует локализацию интерфейса: каталоги сообщений на семь
// языков и определение языка системы нативными средствами (WinAPI на Windows,
// переменные окружения POSIX на Linux/прочих). Фолбек — английский.
package i18n

import (
	"fmt"
	"sync"
)

// Lang — код поддерживаемого языка (ISO 639-1).
type Lang string

const (
	EN Lang = "en"
	RU Lang = "ru"
	FR Lang = "fr"
	DE Lang = "de"
	NL Lang = "nl"
	ES Lang = "es"
	PT Lang = "pt"
)

// catalogs — сообщения по языкам. EN обязателен и служит фолбеком.
var catalogs = map[Lang]map[string]string{
	EN: en,
	RU: ru,
	FR: fr,
	DE: de,
	NL: nl,
	ES: es,
	PT: pt,
}

var (
	mu     sync.RWMutex
	active = EN
)

// Init определяет язык системы и активирует его (фолбек — английский).
func Init() { SetLangCode(detectSystemLang()) }

// SetLangCode активирует язык по коду (например "ru", "fr"). Регион игнорируется
// ("pt-BR" → "pt"). Неизвестный код или пустая строка оставляют текущий язык.
func SetLangCode(code string) {
	if l, ok := resolve(code); ok {
		mu.Lock()
		active = l
		mu.Unlock()
	}
}

// Current возвращает активный язык.
func Current() Lang {
	mu.RLock()
	defer mu.RUnlock()
	return active
}

// resolve сопоставляет код языка (возможно, региональный, например "pt-BR")
// поддерживаемому языку.
func resolve(code string) (Lang, bool) {
	l := Lang(code)
	if _, ok := catalogs[l]; ok {
		return l, true
	}
	return EN, false
}

// T переводит сообщение по ключу для активного языка. Если переданы аргументы,
// результат форматируется через fmt.Sprintf. Порядок фолбека: активный язык →
// английский → сам ключ (чтобы пропуск был заметен, а не «съеден»).
func T(key string, a ...any) string {
	mu.RLock()
	lang := active
	mu.RUnlock()

	s, ok := catalogs[lang][key]
	if !ok {
		if s, ok = catalogs[EN][key]; !ok {
			s = key
		}
	}
	if len(a) > 0 {
		return fmt.Sprintf(s, a...)
	}
	return s
}
