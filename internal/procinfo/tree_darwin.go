//go:build darwin

package procinfo

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

// ParentMap возвращает отображение PID -> PPID через `ps -axo pid=,ppid=`
// (на macOS нет /proc/<pid>/stat, как на Linux). Флаги "=" убирают заголовок.
func ParentMap() map[int]int {
	res := make(map[int]int)
	out, err := exec.Command("ps", "-axo", "pid=,ppid=").Output()
	if err != nil {
		return res
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		res[pid] = ppid
	}
	return res
}
