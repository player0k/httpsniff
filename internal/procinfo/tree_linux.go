//go:build linux

package procinfo

import (
	"os"
	"strconv"
	"strings"
)

// ParentMap возвращает отображение PID -> PPID через /proc/<pid>/stat.
func ParentMap() map[int]int {
	res := make(map[int]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return res
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// Формат: pid (comm) state ppid ...  — comm может содержать пробелы/скобки.
		s := string(data)
		closeIdx := strings.LastIndexByte(s, ')')
		if closeIdx < 0 || closeIdx+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[closeIdx+2:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		res[pid] = ppid
	}
	return res
}
