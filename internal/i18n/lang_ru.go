package i18n

// ru — русский каталог.
var ru = map[string]string{
	"flag.port":            "порт прослушивания прокси",
	"flag.addr":            "адрес (хост) прослушивания прокси",
	"flag.pid":             "перехватывать только трафик процесса с этим PID (0 = все процессы)",
	"flag.caCert":          "путь к сертификату CA (свой или сгенерированный)",
	"flag.caKey":           "путь к приватному ключу CA",
	"flag.maxBody":         "максимум байт тела для вывода (0 = без ограничения)",
	"flag.insecure":        "не проверять сертификаты вышестоящих серверов",
	"flag.systemProxy":     "автоматически включить системный прокси (перехват из коробки)",
	"flag.transparent":     "прозрачный перехват (WinDivert на Windows / iptables на Linux / pf на macOS)",
	"flag.quic":            "перехват HTTP/3 (QUIC/UDP) — требует прозрачного режима",
	"flag.transparentPort": "порт прозрачного перехвата TCP",
	"flag.quicPort":        "UDP-порт перехвата QUIC",
	"flag.logFile":         "дублировать перехват в файл (без ANSI-цветов)",
	"flag.noTUI":           "отключить TUI, выводить лог потоком",
	"flag.tlsMITM":         "в прозрачном режиме расшифровывать HTTPS (MITM); иначе только SNI-хост + проброс",
	"flag.lang":            "язык интерфейса: en, ru, fr, de, nl, es, pt (по умолчанию — язык системы)",

	"main.errCAInit":       "Ошибка инициализации CA: %v",
	"main.errLogOpen":      "Не удалось открыть файл лога: %v",
	"main.errProxy":        "Ошибка прокси: %v",
	"main.warnSysProxy":    "⚠ Не удалось включить системный прокси: %v",
	"main.warnTransparent": "⚠ Прозрачный режим недоступен: %v",
	"main.warnQUIC":        "⚠ Перехват QUIC недоступен: %v",
	"main.shutdown":        "Завершение, восстанавливаю настройки…",
	"main.restored":        "Настройки системного прокси восстановлены.",

	"usage.header": `httpsniff — перехватчик HTTP/HTTPS-трафика (MITM-прокси) для Windows, Linux и macOS

Использование:
  httpsniff [флаги]
  httpsniff winconfig <list|exempt-all|exempt СТРОКА|clear>   (только Windows)
  httpsniff unpin --pid <PID> [--apply|--auto]   отключить проверку TLS у Flutter-приложения
  httpsniff restore                         восстановить настройки прокси после сбоя

Перехват «из коробки» (без ручной настройки прокси в клиенте):
  httpsniff                       # системный прокси включается автоматически
  httpsniff --transparent         # + прозрачный перехват (WinDivert/iptables, нужен админ)
  httpsniff --quic                # + перехват HTTP/3 (QUIC), подразумевает --transparent

Флаги:
`,
	"usage.footer": `
Как пользоваться:
  1. Запустите httpsniff — при первом запуске сгенерируется CA (ca-cert.pem).
  2. Установите ca-cert.pem в доверенные корневые центры сертификации ОС/браузера.
  3. Трафик пойдёт через перехватчик автоматически (системный прокси). Для приложений,
     игнорирующих системный прокси, добавьте --transparent (нужны права администратора).
  4. (Необязательно) Ограничьте перехват одним процессом через --pid <PID>.

Windows 11 — доступ приложений из AppContainer (UWP/WinUI/Store) к прокси:
  httpsniff winconfig exempt-all   # разрешить loopback всем (аналог WinConfig в Fiddler)

`,

	"banner.title":           "httpsniff — перехват HTTP/HTTPS/2/3 трафика",
	"banner.platform":        "Платформа",
	"banner.proxy":           "Прокси",
	"banner.pidFilter":       "Фильтр PID",
	"banner.pidNone":         "(нет — перехват всех процессов)",
	"banner.caCert":          "CA сертиф.",
	"banner.protocols":       "Протоколы",
	"banner.mode":            "Режим",
	"banner.logFile":         "Лог-файл",
	"banner.modeSystem":      "системный прокси",
	"banner.modeExplicit":    "явный прокси",
	"banner.modeTransparent": " + прозрачный",
	"banner.caWarn":          "⚠ Сгенерирован новый CA. Установите его в доверенные корневые\n    центры сертификации, иначе HTTPS-клиенты будут ругаться на сертификат.",
	"banner.installWin":      "Windows: certutil -addstore -f \"ROOT\" %s",
	"banner.installLinux":    "Linux (Debian/Ubuntu): sudo cp %s /usr/local/share/ca-certificates/httpsniff.crt && sudo update-ca-certificates",
	"banner.installMacOS":    "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
	"banner.hotkeys":         "Хоткеи: p — задать PID, a — все процессы, s — статус, q/Ctrl+C — выход.",

	"log.request":        "ЗАПРОС",
	"log.response":       "ОТВЕТ",
	"log.requestBody":    "тело запроса",
	"log.responseBody":   "тело ответа",
	"log.bytes":          "байт",
	"log.decoded":        "декодировано: %s",
	"log.binary":         "[бинарные данные, %d байт, не отображаются]",
	"log.truncated":      "… обрезано (%d из %d байт)",
	"log.error":          "ошибка: %v",
	"log.httpsNoDecrypt": "(без расшифровки)",
	"log.httpsNote":      "тело зашифровано; показан только хост (SNI). Для расшифровки нужен доверенный CA у приложения.",
	"log.mitmRejected":   "MITM отклонён приложением для %s — сертификат не доверен (примените `unpin`); дальше по этому хосту — проброс",

	"ui.status":         "Фильтр: %s   [p] задать PID   [a] все   [s] статус   [q] выход",
	"ui.filterAll":      "все процессы",
	"ui.filterPID":      "PID %d",
	"ui.logToFile":      "[зап. в файл]",
	"ui.captureAll":     "Перехват всех процессов.",
	"ui.help":           "Хоткеи: p — PID, a — все, s — статус, q — выход",
	"ui.pidPrompt":      "PID (Enter — все процессы): ",
	"ui.tuiLogTitle":    " httpsniff — лог (↑/↓, PgUp/PgDn, мышь) ",
	"ui.tuiFilterTitle": " Фильтр по процессу ",
	"ui.tuiPidLabel":    " PID (пусто = все): ",
	"ui.tuiError":       "Ошибка TUI:",

	"sysproxy.hintWin":         "Системный прокси Windows включён (WinINET). Браузеры и приложения,\n  использующие системные настройки, пойдут через перехватчик автоматически.",
	"sysproxy.hintLinux":       "Системный прокси GNOME включён (gsettings). Для перехвата вне GNOME\n  используйте --transparent (iptables REDIRECT).",
	"sysproxy.hintMacOS":       "Системный прокси macOS включён (networksetup) на всех активных сетевых сервисах.\n  Приложения, уважающие системный прокси, пойдут через перехватчик автоматически.",
	"sysproxy.errGsettings":    "gsettings не найден; используйте --transparent или задайте прокси вручную",
	"sysproxy.errNetworksetup": "networksetup не найден; задайте прокси вручную в «Системные настройки › Сеть»",
	"sysproxy.errNoServices":   "не найдено активных сетевых сервисов (networksetup)",
	"sysproxy.errUnsupported":  "автонастройка системного прокси не поддерживается на этой платформе",

	"proxy.quicListen":                "  QUIC/HTTP-3 MITM слушает udp 127.0.0.1:%d (нужен редирект UDP:443 на этот порт)",
	"proxy.transparentWin":            "  Прозрачный перехват через WinDivert активен (TCP 80/443 → :%d)",
	"proxy.transparentLinux":          "  Прозрачный TCP слушает %s. Настройте перенаправление, например:\n    sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports %d",
	"proxy.transparentLinuxActive":    "  Прозрачный TCP слушает %s. iptables REDIRECT настроен автоматически (TCP 80/443 → :%d). Правила будут удалены при выходе.",
	"proxy.errIptablesNotFound":       "iptables не найден; установите iptables или настройте перенаправление вручную",
	"proxy.errIptablesSetup":          "не удалось настроить iptables REDIRECT: %s",
	"proxy.transparentMacOS":          "  Прозрачный TCP слушает %s. Настройте редирект pf, например:\n    echo 'rdr pass on lo0 inet proto tcp to any port {80,443} -> 127.0.0.1 port %d' | sudo pfctl -ef -",
	"proxy.errPfOpen":                 "не удалось открыть /dev/pf (прозрачный режим требует запуска от root)",
	"proxy.errTransparentUnsupported": "прозрачный режим не поддерживается на этой платформе",
	"proxy.errWinDivertMissing":       "WinDivert.dll не найдена рядом с программой; скачайте WinDivert (https://reqrypt.org/windivert.html), положите WinDivert.dll и WinDivert64.sys в папку с httpsniff. Пока используется системный прокси (--system-proxy)",
	"proxy.errAdmin":                  "прозрачный режим требует запуска от имени администратора",

	"wc.usage": `httpsniff winconfig — loopback-исключения AppContainer (аналог WinConfig в Fiddler)

Команды:
  list                показать все AppContainer и их статус исключения
  exempt-all          разрешить loopback ВСЕМ приложениям (Exempt All)
  exempt <строка>     разрешить loopback приложениям, чьё имя/пакет содержит <строку>
  clear               снять все loopback-исключения

Требует прав администратора (кроме list).
`,
	"wc.needSubstr":    "укажите подстроку имени/пакета приложения: httpsniff winconfig exempt <строка>",
	"wc.error":         "Ошибка:",
	"wc.enumErr":       "NetworkIsolationEnumAppContainers вернул код %d",
	"wc.found":         "Найдено AppContainer: %d (✓ = loopback разрешён)",
	"wc.exemptCount":   "Исключений сейчас: %d",
	"wc.exemptAllDone": "✓ Exempt All: loopback разрешён для %d приложений.",
	"wc.noMatch":       "Приложений по запросу \"%s\" не найдено.",
	"wc.exemptDone":    "Готово: добавлено %d, всего исключений %d.",
	"wc.cleared":       "Все loopback-исключения сняты.",
	"wc.setErr":        "NetworkIsolationSetAppContainerConfig вернул код %d ",
	"wc.setErrDenied":  "(отказано в доступе — запустите от имени администратора)",
	"wc.needAdmin":     "⚠ Требуются права администратора. Запустите консоль «от имени администратора».",

	"up.needPid":    "укажите --pid <PID> Flutter-приложения",
	"up.needAdmin":  "⚠ Нужны права администратора для записи в память процесса.",
	"up.sigErr":     "ошибка сигнатуры:",
	"up.moduleErr":  "flutter_windows.dll не найден в процессе %d: %v",
	"up.moduleInfo": "flutter_windows.dll: база=0x%X размер=%d",
	"up.openErr":    "OpenProcess: %v",
	"up.matches":    "совпадений сигнатуры: %d",
	"up.correcting": "функция уже пропатчена старой (возврат 0) версией — исправляю на возврат успеха (1)",
	"up.notFound":   "функция проверки не найдена — возможно, другая версия Flutter (задайте свою --sig)",
	"up.multiple":   "несколько совпадений — из осторожности не патчим. Уточните сигнатуру (--sig).",
	"up.funcAddr":   "функция проверки сертификата: 0x%X",
	"up.dryRun":     "(dry-run) для применения патча добавьте --apply",
	"up.patchErr":   "патч не удался: %v",
	"up.patchOK":    "✓ Проверка TLS отключена. Теперь запустите перехват с --tls-mitm.",
	"up.flagPid":    "PID Flutter-приложения",
	"up.flagApply":  "применить патч (без флага — только поиск/dry-run)",
	"up.flagSig":    "сигнатура функции проверки (hex, ?? — маска)",
	"up.flagAuto":   "автоматический режим: перебрать все известные сигнатуры и применить",
	"up.flagDump":   "показать байты функции до/после патча (диагностика)",

	"up.autoStart":        "Автоматический режим: перебираю известные сигнатуры Flutter/BoringSSL…",
	"up.autoAlreadyPatched": "функция уже пропатчена старой версией (возврат 0) — исправляю на возврат 1",
	"up.autoFound":        "✓ Найдена сигнатура: %s — %s",
	"up.autoNotFound":     "ни одна известная сигнатура не подошла — возможно, очень новая версия Flutter (задайте свою --sig)",
	"up.autoDryRun":       "(dry-run) для применения патча добавьте --apply",
}
