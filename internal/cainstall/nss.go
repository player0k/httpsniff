package cainstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// findCertutil ищет настоящий NSS certutil (из libnss3-tools), пропуская
// Anaconda/conda certutil, который не умеет работать с системными NSS-базами.
func findCertutil() string {
	// Ищем в стандартных путях Linux (ПЕРЕД PATH, чтобы пропустить Anaconda)
	standardPaths := []string{
		"/usr/bin/certutil",
		"/usr/bin/certutil-lg",
		"/usr/sbin/certutil",
	}
	for _, p := range standardPaths {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return p
		}
	}

	// Ищем в PATH, но пропускаем Anaconda/conda
	if path, err := exec.LookPath("certutil"); err == nil {
		if !isAnacondaCertutil(path) {
			return path
		}
	}

	// Пробуем установить libnss3-tools
	if tryInstallLibnss3Tools() {
		for _, p := range standardPaths {
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				return p
			}
		}
	}

	return ""
}

// isAnacondaCertutil проверяет, не из Anaconda/conda ли certutil.
func isAnacondaCertutil(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "anaconda") ||
		strings.Contains(lower, "conda") ||
		strings.Contains(lower, "miniconda") ||
		strings.Contains(lower, "miniforge") ||
		strings.Contains(lower, "mambaforge")
}

// tryInstallLibnss3Tools пытается установить libnss3-tools через apt.
func tryInstallLibnss3Tools() bool {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return false
	}
	out, err := exec.Command("apt-get", "install", "-y", "libnss3-tools").CombinedOutput()
	if err != nil {
		_ = out
		return false
	}
	return true
}

// installNSS устанавливает CA в NSS-базу (Firefox).
// На Linux Firefox читает cert9.db из:
//   - sql:$HOME/.pki/nssdb (общая NSS-база)
//   - sql:$HOME/.mozilla/firefox/<profile>/cert9.db (профиль Firefox)
//
// Примечание: Chrome с 105+ использует свой ChromeRootStore и НЕ читает NSS.
func installNSS(certPath string) (bool, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Sprintf("определение HOME: %v", err)
	}

	certutil := findCertutil()
	if certutil == "" {
		return false, "certutil не найден (установите: sudo apt install libnss3-tools)"
	}

	imported := 0
	var msgs []string

	// 1. Общая NSS-база (~/.pki/nssdb)
	if ok, msg := importIntoNSSDir(certutil, filepath.Join(home, ".pki", "nssdb"), certPath); ok {
		imported++
		msgs = append(msgs, msg)
	}

	// 2. Профили Firefox (~/.mozilla/firefox/<profile>/cert9.db)
	firefoxDir := filepath.Join(home, ".mozilla", "firefox")
	if profiles, err := os.ReadDir(firefoxDir); err == nil {
		for _, p := range profiles {
			if !p.IsDir() {
				continue
			}
			profileDir := filepath.Join(firefoxDir, p.Name())
			if _, err := os.Stat(filepath.Join(profileDir, "cert9.db")); err == nil {
				if ok, msg := importIntoNSSDir(certutil, profileDir, certPath); ok {
					imported++
					msgs = append(msgs, msg)
				}
			}
		}
	}

	if imported == 0 {
		return false, "CA не установлен ни в одну NSS-базу"
	}

	return true, strings.Join(msgs, "; ") + " — перезапустите Firefox"
}

// importIntoNSSDir импортирует CA в указанную NSS-базу (каталог с cert9.db).
func importIntoNSSDir(certutil, nssDir, certPath string) (bool, string) {
	if _, err := os.Stat(nssDir); os.IsNotExist(err) {
		return false, ""
	}

	// Создаём каталог, если нужно
	if err := os.MkdirAll(nssDir, 0700); err != nil {
		return false, ""
	}

	// Инициализируем NSS-базу, если её нет
	dbExists := false
	entries, _ := os.ReadDir(nssDir)
	for _, e := range entries {
		if e.Name() == "cert9.db" || e.Name() == "cert8.db" {
			dbExists = true
			break
		}
	}
	if !dbExists {
		out, err := exec.Command(certutil, "-d", "sql:"+nssDir, "-N", "--empty-password").CombinedOutput()
		if err != nil {
			return false, fmt.Sprintf("инициализация NSS %s: %s: %v", nssDir, string(out), err)
		}
	}

	// Проверяем, не установлен ли уже наш CA
	listOut, _ := exec.Command(certutil, "-d", "sql:"+nssDir, "-L").CombinedOutput()
	if containsNick(listOut, "httpsniff Root CA") {
		return true, fmt.Sprintf("CA уже в %s", nssDir)
	}

	// Импортируем CA
	out, err := exec.Command(certutil, "-d", "sql:"+nssDir, "-A",
		"-t", "C,,",
		"-n", "httpsniff Root CA",
		"-i", certPath,
	).CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("импорт в %s: %s: %v", nssDir, string(out), err)
	}

	return true, fmt.Sprintf("CA в %s", nssDir)
}

func containsNick(output []byte, nick string) bool {
	return strings.Contains(string(output), nick)
}
