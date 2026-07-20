//go:build linux

package cainstall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// installSystem устанавливает CA в системное хранилище Linux
// (Debian/Ubuntu: /usr/local/share/ca-certificates/ + update-ca-certificates;
//  RHEL/CentOS/Fedora: /etc/pki/ca-trust/source/anchors/ + update-ca-trust).
func installSystem(certPath string) (bool, string) {
	// Debian/Ubuntu путь
	debianDir := "/usr/local/share/ca-certificates"
	debianDest := filepath.Join(debianDir, "httpsniff.crt")

	// RHEL/CentOS/Fedora путь
	rhelDir := "/etc/pki/ca-trust/source/anchors"
	rhelDest := filepath.Join(rhelDir, "httpsniff.crt")

	// Пробуем Debian/Ubuntu
	if _, err := os.Stat(debianDir); err == nil {
		return installDebian(certPath, debianDest)
	}

	// Пробуем RHEL/Fedora
	if _, err := os.Stat(rhelDir); err == nil {
		return installRHEL(certPath, rhelDest)
	}

	return false, "неизвестная структура каталогов CA (ни Debian, ни RHEL)"
}

func installDebian(certPath, dest string) (bool, string) {
	src, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Sprintf("чтение CA: %v", err)
	}
	if err := os.WriteFile(dest, src, 0644); err != nil {
		return false, fmt.Sprintf("запись %s: %v (нужен sudo?)", dest, err)
	}

	// update-ca-certificates сам находит .crt в /usr/local/share/ca-certificates/
	// и добавляет в бандл. Не требует записи в ca-certificates.conf.
	exec.Command("update-ca-certificates").Run() // ошибки не фатальны — есть фолбэк

	// Фолбэк: если бандл всё ещё не содержит наш сертификат — дописываем напрямую.
	bundle := "/etc/ssl/certs/ca-certificates.crt"
	if !certInBundle(bundle, "httpsniff") {
		if err := appendFile(bundle, src); err != nil {
			return true, fmt.Sprintf("CA скопирован в %s; обновите бандл: sudo update-ca-certificates", dest)
		}
	}

	return true, fmt.Sprintf("CA установлен в %s (Debian/Ubuntu)", dest)
}

// certInBundle проверяет, содержит ли бандл сертификатов строку-маркер.
func certInBundle(bundlePath, marker string) bool {
	f, err := os.Open(bundlePath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), marker) {
			return true
		}
	}
	return false
}

// appendFile дописывает содержимое в конец файла.
func appendFile(dst string, data []byte) error {
	f, err := os.OpenFile(dst, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

func installRHEL(certPath, dest string) (bool, string) {
	src, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Sprintf("чтение CA: %v", err)
	}
	if err := os.WriteFile(dest, src, 0644); err != nil {
		return false, fmt.Sprintf("запись %s: %v (нужен sudo?)", dest, err)
	}

	out, err := exec.Command("update-ca-trust").CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("update-ca-trust: %s: %v", string(out), err)
	}
	return true, fmt.Sprintf("CA установлен в %s (RHEL/Fedora)", dest)
}
