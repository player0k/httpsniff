// Package cainstall автоматически устанавливает сертификат CA в хранилища
// доверенных сертификатов ОС и браузеров, чтобы MITM-прокси работал «из коробки».
package cainstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// Result содержит результаты автозапуска CA.
type Result struct {
	SystemOK   bool     // CA установлен в системное хранилище
	NSSOK      bool     // CA установлен в NSS (Firefox)
	EnvSet     bool     // NODE_EXTRA_CA_CERTS установлен для текущего процесса
	SystemMsg  string   // сообщение о системном хранилище
	NSSMsg     string   // сообщение о NSS
	EnvMsg     string   // сообщение об env
	Hints      []string // подсказки для приложений (Chrome, Electron, Flutter)
}

// AutoInstall пытается автоматически установить CA во все доступные хранилища.
// certPath — путь к PEM-файлу сертификата CA.
func AutoInstall(certPath string) *Result {
	r := &Result{}

	absCert, err := filepath.Abs(certPath)
	if err != nil {
		absCert = certPath
	}

	// 1. Системное хранилище (platform-specific)
	r.SystemOK, r.SystemMsg = installSystem(absCert)

	// 2. NSS (Firefox)
	r.NSSOK, r.NSSMsg = installNSS(absCert)

	// 3. Переменная окружения для текущего процесса
	r.EnvSet, r.EnvMsg = setEnvCert(absCert)

	// 4. Сбор подсказок для приложений
	r.Hints = collectHints(absCert)

	return r
}

// setEnvCert устанавливает NODE_EXTRA_CA_CERTS для текущего процесса,
// чтобы Electron/Node.js приложения доверяли нашему CA (добавляет к системному CA).
func setEnvCert(certPath string) (bool, string) {
	if _, err := os.Stat(certPath); err != nil {
		return false, fmt.Sprintf("CA not found: %s", certPath)
	}
	os.Setenv("NODE_EXTRA_CA_CERTS", certPath)
	return true, fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", certPath)
}

// collectHints собирает подсказки для приложений, которые используют
// собственные хранилища сертификатов и не доверяют системному CA.
func collectHints(certPath string) []string {
	var hints []string

	// Chrome на Linux (с 105+) использует ChromeRootStore — NSS/системный CA не читает.
	hints = append(hints,
		"Chrome/Chromium на Linux: используйте --ignore-certificate-errors при запуске,",
		"  либо запускайте через CHROME_FLAGS='--ignore-certificate-errors' chromium.",
	)

	// Electron/Node.js apps
	hints = append(hints,
		fmt.Sprintf("Electron/Node.js:NODE_EXTRA_CA_CERTS=%s (уже установлен для этого процесса)", certPath),
	)

	// Flutter/Dart
	hints = append(hints,
		"Flutter/Dart: httpsniff unpin --pid <PID> --auto --apply (только Windows).",
	)

	return hints
}
