//go:build !windows && !linux && !darwin

package procinfo

import (
	"fmt"
	"net"
)

// LookupPID — заглушка для платформ, кроме Windows, Linux и macOS.
// Фильтрация по PID работать не будет (используйте PID 0).
func LookupPID(localIP net.IP, localPort int) (int, error) {
	return 0, fmt.Errorf("определение PID не поддерживается на этой платформе")
}

// ParentMap — заглушка: дерево процессов недоступно на этой платформе.
func ParentMap() map[int]int { return map[int]int{} }
