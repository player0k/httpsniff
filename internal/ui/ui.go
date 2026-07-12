// Package ui реализует интерфейсы вывода перехвата и обработки хоткеев:
// полноэкранный TUI (tview) и потоковый fallback (plainUI).
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"httpsniff/internal/i18n"
)

// UI — абстракция вывода лога и обработки хоткеев.
type UI interface {
	Log(block string)      // добавить блок лога
	SetStatus(text string) // обновить строку статуса
	Run(onQuit func())     // запустить обработку ввода (блокирует)
	Stop()                 // восстановить терминал/освободить ресурсы
}

// Controller — то, что UI требуется от ядра: чтение/смена PID-фильтра и признак
// записи в файл. Реализуется *proxy.Proxy (интерфейс объявлен на стороне UI,
// чтобы не зависеть от пакета proxy).
type Controller interface {
	FilterPID() int
	SetFilterPID(pid int)
	LoggingToFile() bool
}

// statusLine формирует строку статуса из состояния контроллера.
func statusLine(c Controller) string {
	filt := i18n.T("ui.filterAll")
	if fp := c.FilterPID(); fp != 0 {
		filt = i18n.T("ui.filterPID", fp)
	}
	return i18n.T("ui.status", filt)
}

// ---- plainUI: потоковый вывод + хоткеи (fallback, когда TUI отключён/недоступен) ----

// NewPlain создаёт потоковый UI, управляющий фильтром через контроллер.
func NewPlain(ctrl Controller) UI { return &plainUI{ctrl: ctrl} }

type plainUI struct {
	ctrl      Controller
	termFD    int
	termState *term.State
}

func (u *plainUI) Log(block string)      { fmt.Print(block) }
func (u *plainUI) SetStatus(text string) {}
func (u *plainUI) Stop()                 { u.restoreTerminal() }

func (u *plainUI) restoreTerminal() {
	if u.termState != nil {
		term.Restore(u.termFD, u.termState)
		u.termState = nil
	}
}

func (u *plainUI) Run(onQuit func()) {
	u.termFD = int(os.Stdin.Fd())
	st, err := term.MakeRaw(u.termFD)
	if err != nil {
		u.runLine(onQuit)
		return
	}
	u.termState = st
	u.printHelp()
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		switch buf[0] {
		case 'p', 'P':
			u.ctrl.SetFilterPID(u.promptPID())
			u.printStatus()
		case 'a', 'A':
			u.ctrl.SetFilterPID(0)
			u.printf("%s", i18n.T("ui.captureAll"))
		case 's', 'S':
			u.printStatus()
		case 'h', 'H', '?':
			u.printHelp()
		case 'q', 'Q', 3:
			u.restoreTerminal()
			onQuit()
			return
		}
	}
}

func (u *plainUI) promptPID() int {
	fmt.Printf("\r\n\033[1;36m%s\033[0m", i18n.T("ui.pidPrompt"))
	var sb strings.Builder
	b := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(b)
		if err != nil || n == 0 {
			break
		}
		c := b[0]
		switch {
		case c == '\r' || c == '\n':
			fmt.Print("\r\n")
			if sb.Len() == 0 {
				return 0
			}
			v, _ := strconv.Atoi(sb.String())
			return v
		case c == 127 || c == 8:
			if sb.Len() > 0 {
				s := sb.String()
				sb.Reset()
				sb.WriteString(s[:len(s)-1])
				fmt.Print("\b \b")
			}
		case c >= '0' && c <= '9':
			sb.WriteByte(c)
			fmt.Printf("%c", c)
		case c == 3:
			fmt.Print("\r\n")
			return u.ctrl.FilterPID()
		}
	}
	return u.ctrl.FilterPID()
}

func (u *plainUI) runLine(onQuit func()) {
	u.printHelp()
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "p":
			pid := 0
			if len(fields) > 1 {
				pid, _ = strconv.Atoi(fields[1])
			}
			u.ctrl.SetFilterPID(pid)
			u.printStatus()
		case "a", "all":
			u.ctrl.SetFilterPID(0)
			u.printf("%s", i18n.T("ui.captureAll"))
		case "s", "status":
			u.printStatus()
		case "h", "help", "?":
			u.printHelp()
		case "q", "quit", "exit":
			onQuit()
			return
		}
	}
}

func (u *plainUI) printStatus() { u.printf("%s", statusLine(u.ctrl)) }

func (u *plainUI) printHelp() {
	u.printf("%s", i18n.T("ui.help"))
}

func (u *plainUI) printf(format string, a ...any) {
	fmt.Printf("\r\033[1;35m▷ \033[0m"+format+"\r\n", a...)
}
