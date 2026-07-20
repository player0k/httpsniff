// Command httpsniff — перехватчик HTTP/HTTPS/2/3-трафика (MITM-прокси) для
// Windows, Linux и macOS: расшифровка TLS «на лету», фильтрация по PID, TUI и хоткеи.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"

	"httpsniff/internal/ca"
	"httpsniff/internal/cainstall"
	"httpsniff/internal/i18n"
	"httpsniff/internal/proxy"
	"httpsniff/internal/sysproxy"
	"httpsniff/internal/ui"
	"httpsniff/internal/unpin"
	"httpsniff/internal/winconfig"
)

func main() {
	i18n.Init() // язык по системным настройкам (фолбек — английский)

	if dispatchSubcommand(os.Args[1:]) {
		return
	}

	// Переопределение флагом --lang применяем ДО разбора флагов, чтобы
	// локализовать и вывод --help (flag.Usage вызывается внутри flag.Parse).
	i18n.SetLangCode(langFromArgs(os.Args[1:]))

	cfg := parseFlags()

	authority, generated, err := ca.LoadOrCreate(cfg.caCert, cfg.caKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("main.errCAInit", err))
		os.Exit(1)
	}

	p := proxy.New(authority, cfg.pid, cfg.maxBody, cfg.insecure)
	p.SetTLSMITM(cfg.tlsMITM)

	// Выбор интерфейса: TUI, если stdout — терминал и не задан --no-tui.
	var iface ui.UI
	if !cfg.noTUI && term.IsTerminal(int(os.Stdout.Fd())) {
		iface = ui.NewTview(p)
	} else {
		iface = ui.NewPlain(p)
	}
	p.SetLogger(iface)

	// Автоустановка CA в системное хранилище и NSS (Firefox).
	// Выполняется тихо: ошибки не фатальны, пользователю выводятся подсказки.
	if cfg.tlsMITM || cfg.transparent {
		installResult := cainstall.AutoInstall(cfg.caCert)
		if installResult.SystemOK {
			iface.Log(fmt.Sprintf("\033[1;32m✓ %s\033[0m\n", installResult.SystemMsg))
		}
		if installResult.NSSOK {
			iface.Log(fmt.Sprintf("\033[1;32m✓ %s\033[0m\n", installResult.NSSMsg))
		}
		if installResult.EnvSet {
			iface.Log(fmt.Sprintf("\033[2m  %s\033[0m\n", installResult.EnvMsg))
		}
		for _, h := range installResult.Hints {
			iface.Log(fmt.Sprintf("\033[1;33m  %s\033[0m\n", h))
		}
	}

	var cleanups []func()

	// Auto-unpin: фоновый обход новых процессов с flutter_windows.dll (Windows)
	// и мгновенная попытка при MITM-reject. Для curl/браузеров не нужен —
	// им достаточно CA в системном store.
	if cfg.autoUnpin && cfg.tlsMITM && unpin.Supported() {
		w := unpin.StartWatcher(iface.Log, func(pid int) {
			// После успешного патча снова пробуем MITM по всем хостам.
			p.ClearMITMFailed()
		})
		cleanups = append(cleanups, w.Stop)
		p.SetOnMITMRejected(func(pid int, host string) {
			res := w.TryPID(pid)
			if res.Applied {
				p.ClearMITMFailed()
				return
			}
			// Не Flutter: подсказка про CA, а не про unpin.
			if res.Skipped && pid > 0 {
				iface.Log(fmt.Sprintf("\033[2m  %s\033[0m\n", i18n.T("log.mitmHintCA", pid)))
			}
		})
		iface.Log(fmt.Sprintf("\033[2m  %s\033[0m\n", i18n.T("main.autoUnpinOn")))
	}

	// Файл лога.
	if cfg.logFile != "" {
		f, err := os.OpenFile(cfg.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("main.errLogOpen", err))
			os.Exit(1)
		}
		p.SetLogFile(f)
		cleanups = append(cleanups, func() { f.Close() })
	}

	// Основной прокси-листенер.
	go func() {
		if err := p.ListenAndServe(cfg.listenAddr); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("main.errProxy", err))
			os.Exit(1)
		}
	}()

	// Системный прокси (перехват из коробки).
	if cfg.sysProxy {
		restore, err := sysproxy.Enable(cfg.listenAddr)
		if err != nil {
			iface.Log(fmt.Sprintf("\033[1;33m%s\033[0m\n", i18n.T("main.warnSysProxy", err)))
		} else {
			cleanups = append(cleanups, restore)
		}
	}

	// Прозрачный перехват TCP (WinDivert / iptables).
	if cfg.transparent || cfg.quic {
		tAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.tPort))
		stop, err := p.ServeTransparent(tAddr, cfg.tPort)
		if err != nil {
			iface.Log(fmt.Sprintf("\033[1;33m%s\033[0m\n", i18n.T("main.warnTransparent", err)))
		} else {
			cleanups = append(cleanups, stop)
		}
	}

	// Перехват HTTP/3 (QUIC).
	if cfg.quic {
		stop, err := p.ServeQUIC(cfg.qPort)
		if err != nil {
			iface.Log(fmt.Sprintf("\033[1;33m%s\033[0m\n", i18n.T("main.warnQUIC", err)))
		} else {
			cleanups = append(cleanups, stop)
		}
	}

	iface.Log(bannerText(cfg, generated))

	// Единая точка завершения: сигнал (Ctrl+C) или хоткей 'q'.
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; iface.Stop(); finish() }()

	go iface.Run(finish)

	<-done
	iface.Stop()
	fmt.Println("\n" + i18n.T("main.shutdown"))
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

// dispatchSubcommand обрабатывает подкоманды (winconfig/restore/unpin) и
// возвращает true, если подкоманда была исполнена.
func dispatchSubcommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "winconfig":
		// Управление loopback-исключениями AppContainer (аналог WinConfig в Fiddler).
		winconfig.Run(args[1:])
	case "restore":
		// Восстановить настройки прокси после аварийного выхода.
		sysproxy.Recover()
		fmt.Println(i18n.T("main.restored"))
	case "unpin":
		// Отключить проверку TLS у Flutter-приложения (для расшифровки).
		unpin.Run(args[1:])
	default:
		return false
	}
	return true
}

// langFromArgs извлекает значение флага --lang/-lang из аргументов до полного
// разбора флагов (формы "--lang ru", "-lang=ru"). Пустая строка — не задан.
func langFromArgs(args []string) string {
	for i, a := range args {
		switch {
		case a == "--lang" || a == "-lang":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "--lang="):
			return strings.TrimPrefix(a, "--lang=")
		case strings.HasPrefix(a, "-lang="):
			return strings.TrimPrefix(a, "-lang=")
		}
	}
	return ""
}

// config — разобранная конфигурация запуска перехватчика.
type config struct {
	listenAddr  string
	pid         int
	caCert      string
	caKey       string
	maxBody     int
	insecure    bool
	sysProxy    bool
	transparent bool
	quic        bool
	tPort       int
	qPort       int
	logFile     string
	noTUI       bool
	tlsMITM     bool
	autoUnpin   bool
	lang        string
}

func parseFlags() config {
	var (
		port        = flag.Int("port", 8888, i18n.T("flag.port"))
		addr        = flag.String("addr", "127.0.0.1", i18n.T("flag.addr"))
		pid         = flag.Int("pid", 0, i18n.T("flag.pid"))
		caCert      = flag.String("ca-cert", "ca-cert.pem", i18n.T("flag.caCert"))
		caKey       = flag.String("ca-key", "ca-key.pem", i18n.T("flag.caKey"))
		maxBody     = flag.Int("max-body", 8192, i18n.T("flag.maxBody"))
		insecure    = flag.Bool("insecure", false, i18n.T("flag.insecure"))
		sysProxy    = flag.Bool("system-proxy", true, i18n.T("flag.systemProxy"))
		transparent = flag.Bool("transparent", false, i18n.T("flag.transparent"))
		quic        = flag.Bool("quic", false, i18n.T("flag.quic"))
		tPort       = flag.Int("transparent-port", 8889, i18n.T("flag.transparentPort"))
		qPort       = flag.Int("quic-port", 8890, i18n.T("flag.quicPort"))
		logFilePath = flag.String("log-file", "", i18n.T("flag.logFile"))
		noTUI       = flag.Bool("no-tui", false, i18n.T("flag.noTUI"))
		tlsMITM     = flag.Bool("tls-mitm", false, i18n.T("flag.tlsMITM"))
		// По умолчанию включён: при --tls-mitm на Windows автоматически
		// патчит новые Flutter-процессы (curl/браузерам не нужен — им CA).
		autoUnpin = flag.Bool("auto-unpin", true, i18n.T("flag.autoUnpin"))
		lang      = flag.String("lang", "", i18n.T("flag.lang"))
	)
	flag.Usage = usage
	flag.Parse()

	listenAddr := *addr
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		listenAddr = net.JoinHostPort(*addr, strconv.Itoa(*port))
	}

	return config{
		listenAddr:  listenAddr,
		pid:         *pid,
		caCert:      *caCert,
		caKey:       *caKey,
		maxBody:     *maxBody,
		insecure:    *insecure,
		sysProxy:    *sysProxy,
		transparent: *transparent,
		quic:        *quic,
		tPort:       *tPort,
		qPort:       *qPort,
		logFile:     *logFilePath,
		noTUI:       *noTUI,
		tlsMITM:     *tlsMITM,
		autoUnpin:   *autoUnpin,
		lang:        *lang,
	}
}
