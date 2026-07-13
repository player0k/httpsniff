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
	SystemOK   bool   // CA установлен в системное хранилище
	NSSOK      bool   // CA установлен в NSS (Firefox/Chrome)
	EnvSet     bool   // SSL_CERT_FILE установлен для текущего процесса
	SystemMsg  string // сообщение о системном хранилище
	NSSMsg     string // сообщение о NSS
	EnvMsg     string // сообщение об env
	Hint       string // дополнительная подсказка (например, для Flutter)
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

	// 2. NSS (Firefox/Chrome)
	r.NSSOK, r.NSSMsg = installNSS(absCert)

	// 3. Переменная окружения для текущего процесса
	r.EnvSet, r.EnvMsg = setEnvCert(absCert)

	// 4. Подсказка для Flutter/Dart
	r.Hint = flutterHint()

	return r
}

// setEnvCert устанавливает SSL_CERT_FILE для текущего процесса,
// чтобы Go, Python, curl и другие инструменты, читающие эту переменную,
// доверяли нашему CA.
func setEnvCert(certPath string) (bool, string) {
	if _, err := os.Stat(certPath); err != nil {
		return false, fmt.Sprintf("CA not found: %s", certPath)
	}
	os.Setenv("SSL_CERT_FILE", certPath)
	return true, fmt.Sprintf("SSL_CERT_FILE=%s", certPath)
}

func flutterHint() string {
	return "For Flutter/Dart apps: use `httpsniff unpin --pid <PID> --auto --apply` (Windows only)"
}
