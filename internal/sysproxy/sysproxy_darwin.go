//go:build darwin

package sysproxy

import (
	"bufio"
	"errors"
	"net"
	"os/exec"
	"strings"

	"httpsniff/internal/i18n"
)

// Enable включает системный HTTP/HTTPS-прокси macOS через networksetup для всех
// активных сетевых сервисов (Wi-Fi, Ethernet и т. п.). Восстановление —
// возвращаемая функция выключает прокси на тех же сервисах.
func Enable(hostPort string) (func(), error) {
	if _, err := exec.LookPath("networksetup"); err != nil {
		return nil, errors.New(i18n.T("sysproxy.errNetworksetup"))
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	// Прокси на 127.0.0.1 не перехватит трафик приложений, обращающихся к
	// «настоящему» IP хоста; для localhost networksetup всё равно корректен.
	services := networkServices()
	if len(services) == 0 {
		return nil, errors.New(i18n.T("sysproxy.errNoServices"))
	}

	for _, svc := range services {
		exec.Command("networksetup", "-setwebproxy", svc, host, port).Run()
		exec.Command("networksetup", "-setsecurewebproxy", svc, host, port).Run()
		exec.Command("networksetup", "-setwebproxystate", svc, "on").Run()
		exec.Command("networksetup", "-setsecurewebproxystate", svc, "on").Run()
	}

	restore := func() {
		for _, svc := range services {
			exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
			exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
		}
	}
	return restore, nil
}

// Recover выключает HTTP/HTTPS-прокси на всех активных сетевых сервисах
// (ручное восстановление после аварийного выхода).
func Recover() {
	if _, err := exec.LookPath("networksetup"); err != nil {
		return
	}
	for _, svc := range networkServices() {
		exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
		exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
	}
}

// Hint возвращает подсказку о поведении системного прокси на macOS.
func Hint() string { return i18n.T("sysproxy.hintMacOS") }

// networkServices возвращает список активных сетевых сервисов macOS. Сервисы,
// помеченные звёздочкой (отключённые), пропускаются.
func networkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var res []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			// Первая строка — пояснение ("An asterisk (*) denotes...").
			first = false
			continue
		}
		if line == "" || strings.HasPrefix(line, "*") {
			continue // отключённый сервис
		}
		res = append(res, line)
	}
	return res
}
