package cainstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// installNSS устанавливает CA в NSS-базу (Firefox/Chrome).
// Работает на Linux и macOS: sql:$HOME/.pki/nssdb
func installNSS(certPath string) (bool, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Sprintf("определение HOME: %v", err)
	}

	nssDir := filepath.Join(home, ".pki", "nssdb")

	// Проверяем наличие certutil (NSS)
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return false, "certutil не найден (установите libnss3-tools)"
	}

	// Создаём каталог NSS, если его нет
	if _, err := os.Stat(nssDir); os.IsNotExist(err) {
		if err := os.MkdirAll(nssDir, 0700); err != nil {
			return false, fmt.Sprintf("создание %s: %v", nssDir, err)
		}
	}

	// Проверяем, инициализирована ли уже NSS-база
	dbExists := false
	entries, _ := os.ReadDir(nssDir)
	for _, e := range entries {
		if e.Name() == "cert9.db" || e.Name() == "cert8.db" {
			dbExists = true
			break
		}
	}

	// Инициализируем, если нужно
	if !dbExists {
		out, err := exec.Command(certutil, "-d", "sql:"+nssDir, "-N", "--empty-password").CombinedOutput()
		if err != nil {
			return false, fmt.Sprintf("инициализация NSS: %s: %v", string(out), err)
		}
	}

	// Проверяем, не установлен ли уже наш CA
	listOut, _ := exec.Command(certutil, "-d", "sql:"+nssDir, "-L").CombinedOutput()
	if containsNick(listOut, "httpsniff Root CA") {
		return true, fmt.Sprintf("CA уже установлен в NSS (%s)", nssDir)
	}

	// Импортируем CA
	out, err := exec.Command(certutil, "-d", "sql:"+nssDir, "-A",
		"-t", "C,,",
		"-n", "httpsniff Root CA",
		"-i", certPath,
	).CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("импорт в NSS: %s: %v", string(out), err)
	}

	return true, fmt.Sprintf("CA установлен в NSS (%s) — Firefox/Chrome увидят его после перезапуска", nssDir)
}

func containsNick(output []byte, nick string) bool {
	return strings.Contains(string(output), nick)
}
