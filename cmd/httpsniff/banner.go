package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"

	"httpsniff/internal/i18n"
	"httpsniff/internal/sysproxy"
)

func usage() {
	fmt.Fprint(os.Stderr, i18n.T("usage.header"))
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, i18n.T("usage.footer"))
}

func bannerText(cfg config, generated bool) string {
	var b strings.Builder
	b.WriteString(box(i18n.T("banner.title")))

	protoSuffix := ""
	if cfg.quic {
		protoSuffix = ", HTTP/3 (QUIC)"
	}

	pidVal := i18n.T("banner.pidNone")
	if cfg.pid != 0 {
		pidVal = fmt.Sprintf("%d", cfg.pid)
	}

	rows := [][2]string{
		{i18n.T("banner.platform"), runtime.GOOS + "/" + runtime.GOARCH},
		{i18n.T("banner.proxy"), "http://" + cfg.listenAddr},
		{i18n.T("banner.pidFilter"), pidVal},
		{i18n.T("banner.caCert"), cfg.caCert},
		{i18n.T("banner.protocols"), "HTTP/1.0, HTTP/1.1, HTTP/2" + protoSuffix},
		{i18n.T("banner.mode"), modeText(cfg)},
	}
	if cfg.logFile != "" {
		rows = append(rows, [2]string{i18n.T("banner.logFile"), cfg.logFile})
	}

	width := 0
	for _, r := range rows {
		if w := utf8.RuneCountInString(r[0]); w > width {
			width = w
		}
	}
	for _, r := range rows {
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(r[0]))
		fmt.Fprintf(&b, "  %s%s : %s\n", r[0], pad, r[1])
	}

	if generated {
		fmt.Fprintf(&b, "\033[1;33m  %s\033[0m\n", i18n.T("banner.caWarn"))
		if h := installHint(cfg.caCert); h != "" {
			fmt.Fprintf(&b, "\033[2m    %s\033[0m\n", h)
		}
	}
	if cfg.sysProxy {
		if h := sysproxy.Hint(); h != "" {
			fmt.Fprintf(&b, "\033[2m  %s\033[0m\n", h)
		}
	}
	fmt.Fprintf(&b, "\033[2m  %s\033[0m\n", i18n.T("banner.hotkeys"))
	return b.String()
}

// modeText формирует локализованное описание режима перехвата.
func modeText(cfg config) string {
	mode := i18n.T("banner.modeSystem")
	if !cfg.sysProxy {
		mode = i18n.T("banner.modeExplicit")
	}
	if cfg.transparent || cfg.quic {
		mode += i18n.T("banner.modeTransparent")
	}
	return mode
}

// box рисует рамку вокруг строки заголовка, подстраивая ширину под её длину
// (важно для локализованных заголовков разной длины).
func box(title string) string {
	inner := utf8.RuneCountInString(title) + 4
	line := strings.Repeat("═", inner)
	var b strings.Builder
	b.WriteString("\033[1;36m╔" + line + "╗\n")
	b.WriteString("║  " + title + "  ║\n")
	b.WriteString("╚" + line + "╝\033[0m\n")
	return b.String()
}

func installHint(caCert string) string {
	switch runtime.GOOS {
	case "windows":
		return i18n.T("banner.installWin", caCert)
	case "linux":
		return i18n.T("banner.installLinux", caCert)
	case "darwin":
		return i18n.T("banner.installMacOS", caCert)
	}
	return ""
}
