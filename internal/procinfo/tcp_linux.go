//go:build linux

package procinfo

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// LookupPID находит PID процесса по локальному TCP-порту:
// 1) в /proc/net/tcp{,6} по порту находим inode сокета;
// 2) сканируем /proc/<pid>/fd/* в поисках ссылки socket:[inode].
func LookupPID(localIP net.IP, localPort int) (int, error) {
	inode, err := inodeForPort(localPort)
	if err != nil {
		return 0, err
	}
	return pidForInode(inode)
}

func inodeForPort(port int) (string, error) {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if inode, ok := scanProcNet(path, port); ok {
			return inode, nil
		}
	}
	return "", fmt.Errorf("сокет для порта %d не найден", port)
}

func scanProcNet(path string, port int) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // пропускаем заголовок
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// local_address имеет вид HEXIP:HEXPORT
		local := fields[1]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		p, err := strconv.ParseInt(local[idx+1:], 16, 32)
		if err != nil {
			continue
		}
		if int(p) == port {
			return fields[9], true // inode
		}
	}
	return "", false
}

func pidForInode(inode string) (int, error) {
	target := "socket:[" + inode + "]"

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}
		fdDir := "/proc/" + proc.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if link == target {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("процесс с сокетом inode=%s не найден", inode)
}
