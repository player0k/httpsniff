//go:build !windows

package i18n

import (
	"os"
	"strings"
)

// detectSystemLang определяет язык по переменным окружения POSIX (стандарт
// Linux/Unix): LC_ALL, затем LC_MESSAGES, затем LANG. Значение вида
// "ru_RU.UTF-8" сводится к коду языка "ru".
func detectSystemLang() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := os.Getenv(key)
		if v == "" || v == "C" || v == "POSIX" {
			continue
		}
		v = strings.SplitN(v, ".", 2)[0] // отбросить кодировку (.UTF-8)
		v = strings.SplitN(v, "_", 2)[0] // отбросить регион (_RU)
		v = strings.SplitN(v, "@", 2)[0] // отбросить модификатор (@euro)
		return strings.ToLower(v)
	}
	return "en"
}
