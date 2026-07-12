//go:build !windows

package unpin

import (
	"fmt"
	"os"
)

// Run — заглушка: обход TLS Flutter доступен только в Windows.
func Run(args []string) {
	fmt.Fprintln(os.Stderr, "Подкоманда unpin (обход TLS Flutter) доступна только в Windows.")
	os.Exit(2)
}
