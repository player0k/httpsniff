//go:build linux

package cainstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	// Копируем сертификат
	src, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Sprintf("чтение CA: %v", err)
	}
	if err := os.WriteFile(dest, src, 0644); err != nil {
		return false, fmt.Sprintf("запись %s: %v (нужен sudo?)", dest, err)
	}

	// update-ca-certificates
	out, err := exec.Command("update-ca-certificates").CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("update-ca-certificates: %s: %v", string(out), err)
	}
	return true, fmt.Sprintf("CA установлен в %s (Debian/Ubuntu)", dest)
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
