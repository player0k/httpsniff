//go:build windows

package cainstall

import (
	"fmt"
	"os"
	"os/exec"
)

// installSystem устанавливает CA в системное хранилище Windows
// (ROOT store через certutil).
func installSystem(certPath string) (bool, string) {
	if _, err := exec.LookPath("certutil"); err != nil {
		return false, "certutil не найден"
	}

	out, err := exec.Command("certutil", "-addstore", "-f", "ROOT", certPath).CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("certutil: %s: %v", string(out), err)
	}
	return true, "CA установлен в ROOT store (Windows)"
}
