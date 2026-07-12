//go:build darwin

// Package procinfo на macOS определяет PID процесса-владельца TCP-порта через
// lsof (в системе нет /proc, как на Linux) и строит дерево процессов через ps.
package procinfo

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// LookupPID находит PID процесса по локальному TCP-порту через lsof.
//
// Клиент подключается к нашему прокси со своего эфемерного локального порта
// localPort. Запрашиваем у lsof все ESTABLISHED-сокеты этого порта в машинном
// формате (-F) и выбираем тот, у которого localPort стоит в ЛЕВОЙ части
// "laddr:lport->faddr:fport" — это сокет клиента, а не самого прокси.
func LookupPID(localIP net.IP, localPort int) (int, error) {
	cmd := exec.Command("lsof", "-nP",
		"-iTCP:"+strconv.Itoa(localPort),
		"-sTCP:ESTABLISHED",
		"-Fpn")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("lsof для порта %d: %w", localPort, err)
	}

	var curPID int
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 1 {
			continue
		}
		switch line[0] {
		case 'p':
			curPID, _ = strconv.Atoi(line[1:])
		case 'n':
			if isLocalPort(line[1:], localPort) {
				return curPID, nil
			}
		}
	}
	return 0, fmt.Errorf("сокет для порта %d не найден", localPort)
}

// isLocalPort сообщает, стоит ли port в ЛЕВОЙ (локальной) части имени сокета
// вида "127.0.0.1:54321->127.0.0.1:8888".
func isLocalPort(name string, port int) bool {
	arrow := strings.Index(name, "->")
	if arrow < 0 {
		return false
	}
	left := name[:arrow]
	colon := strings.LastIndex(left, ":")
	if colon < 0 {
		return false
	}
	p, err := strconv.Atoi(left[colon+1:])
	return err == nil && p == port
}
