//go:build linux

package sysproxy

import (
	"errors"
	"net"
	"os/exec"

	"httpsniff/internal/i18n"
)

// Enable включает системный прокси в GNOME через gsettings (best-effort).
// Для полного «прозрачного» перехвата на Linux используйте режим --transparent
// (iptables REDIRECT), он не зависит от окружения рабочего стола.
func Enable(hostPort string) (func(), error) {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil, errors.New(i18n.T("sysproxy.errGsettings"))
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	set := func(schema, key, val string) {
		exec.Command("gsettings", "set", schema, key, val).Run()
	}

	set("org.gnome.system.proxy", "mode", "manual")
	set("org.gnome.system.proxy.http", "host", host)
	set("org.gnome.system.proxy.http", "port", port)
	set("org.gnome.system.proxy.https", "host", host)
	set("org.gnome.system.proxy.https", "port", port)

	restore := func() {
		set("org.gnome.system.proxy", "mode", "none")
	}
	return restore, nil
}

// Recover сбрасывает системный прокси GNOME в none (ручное восстановление).
func Recover() {
	if _, err := exec.LookPath("gsettings"); err == nil {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	}
}

// Hint возвращает подсказку о поведении системного прокси на этой платформе.
func Hint() string { return i18n.T("sysproxy.hintLinux") }
