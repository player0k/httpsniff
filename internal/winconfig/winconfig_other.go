//go:build !windows

package winconfig

import (
	"fmt"
	"os"
)

// Run — заглушка: управление AppContainer доступно только в Windows.
func Run(args []string) {
	fmt.Fprintln(os.Stderr, "Подкоманда winconfig доступна только в Windows.")
	os.Exit(2)
}
