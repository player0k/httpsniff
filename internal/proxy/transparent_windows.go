//go:build windows

package proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"httpsniff/internal/i18n"
)

// ServeTransparent на Windows перенаправляет исходящий TCP выбранных процессов
// на локальный порт перехватчика через WinDivert и обслуживает эти соединения,
// восстанавливая исходный адрес назначения из таблицы редиректора.
//
// Требуется драйвер WinDivert (WinDivert.dll + WinDivert64.sys рядом с программой)
// и запуск от имени администратора. Без него используется системный прокси.
func (p *Proxy) ServeTransparent(addr string, tport int) (func(), error) {
	dll := locateWinDivert()
	if dll == "" {
		return nil, errors.New(i18n.T("proxy.errWinDivertMissing"))
	}
	if !isAdminWin() {
		return nil, errors.New(i18n.T("proxy.errAdmin"))
	}

	rd, err := newWinDivertRedirector(dll, tport, os.Getpid(), p.matches)
	if err != nil {
		return nil, err
	}

	// Локальный листенер на 0.0.0.0:tport — сюда WinDivert заворачивает трафик.
	ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(tport)))
	if err != nil {
		return nil, err
	}
	if err := rd.start(); err != nil {
		ln.Close()
		return nil, err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serveRedirected(conn, rd)
		}
	}()

	fmt.Printf("\033[2m%s\033[0m\n", i18n.T("proxy.transparentWin", tport))
	return func() {
		ln.Close()
		rd.stopRedirect()
	}, nil
}

func (p *Proxy) serveRedirected(conn net.Conn, rd *winDivertRedirector) {
	_, portStr, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		conn.Close()
		return
	}
	cport, _ := strconv.Atoi(portStr)
	origDst, ok := rd.OrigDst(uint16(cport))
	if !ok {
		conn.Close()
		return
	}
	pid := p.clientPID(conn)
	p.HandleTransparent(conn, origDst, pid)
}

func locateWinDivert() string {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "WinDivert.dll")
		if fileExists(cand) {
			return cand
		}
	}
	if fileExists("WinDivert.dll") {
		return "WinDivert.dll"
	}
	return ""
}

func isAdminWin() bool {
	proc := syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin")
	r, _, _ := proc.Call()
	return r != 0
}
