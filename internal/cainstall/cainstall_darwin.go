//go:build darwin

package cainstall

import (
	"fmt"
	"os/exec"
)

// installSystem устанавливает CA в системное хранилище macOS
// (System.keychain через security add-trusted-cert).
func installSystem(certPath string) (bool, string) {
	// Проверяем, что security доступен
	if _, err := exec.LookPath("security"); err != nil {
		return false, "команда 'security' не найдена"
	}

	out, err := exec.Command("security", "add-trusted-cert",
		"-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		certPath,
	).CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("security add-trusted-cert: %s: %v (нужен sudo?)", string(out), err)
	}
	return true, "CA установлен в System.keychain (macOS)"
}
