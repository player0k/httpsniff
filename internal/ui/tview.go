package ui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"httpsniff/internal/i18n"
)

// tviewUI — полноэкранный TUI: прокручиваемый лог сверху, строка статуса снизу,
// модальный ввод PID. Лог не перебивает ввод — области экрана разделены.
type tviewUI struct {
	app     *tview.Application
	logView *tview.TextView
	status  *tview.TextView
	pages   *tview.Pages
	pidIn   *tview.InputField
	ctrl    Controller
	pidOpen bool
}

// NewTview создаёт полноэкранный TUI, управляющий фильтром через контроллер.
func NewTview(ctrl Controller) UI { return newTview(ctrl) }

func newTview(ctrl Controller) *tviewUI {
	app := tview.NewApplication()

	logView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	logView.SetMaxLines(5000)
	logView.SetChangedFunc(func() { app.Draw() })
	logView.SetBorder(true).SetTitle(i18n.T("ui.tuiLogTitle"))

	status := tview.NewTextView().SetDynamicColors(true)
	status.SetTextColor(tcell.ColorWhite)
	status.SetBackgroundColor(tcell.ColorNavy)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(logView, 0, 1, true).
		AddItem(status, 1, 1, false)

	pidIn := tview.NewInputField().SetLabel(i18n.T("ui.tuiPidLabel")).SetFieldWidth(12)
	pidIn.SetBorder(true).SetTitle(i18n.T("ui.tuiFilterTitle"))

	pages := tview.NewPages().
		AddPage("main", flex, true, true).
		AddPage("pid", center(pidIn, 40, 3), true, false)

	u := &tviewUI{app: app, logView: logView, status: status, pages: pages, pidIn: pidIn, ctrl: ctrl}

	pidIn.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			t := strings.TrimSpace(u.pidIn.GetText())
			pid := 0
			if t != "" {
				pid, _ = strconv.Atoi(t)
			}
			u.ctrl.SetFilterPID(pid)
		}
		u.pages.HidePage("pid")
		u.pidOpen = false
		u.app.SetFocus(u.logView)
		u.refreshStatus()
	})

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if u.pidOpen {
			if ev.Key() == tcell.KeyEscape {
				u.pages.HidePage("pid")
				u.pidOpen = false
				u.app.SetFocus(u.logView)
				u.refreshStatus()
				return nil
			}
			return ev // ввод обрабатывает поле PID
		}
		if ev.Key() == tcell.KeyCtrlC {
			u.app.Stop()
			return nil
		}
		switch ev.Rune() {
		case 'p', 'P':
			u.openPID()
			return nil
		case 'a', 'A':
			u.ctrl.SetFilterPID(0)
			u.refreshStatus()
			return nil
		case 's', 'S':
			u.refreshStatus()
			return nil
		case 'q', 'Q':
			u.app.Stop()
			return nil
		}
		return ev
	})

	app.SetRoot(pages, true).EnableMouse(true).SetFocus(logView)
	u.refreshStatus()
	return u
}

func (u *tviewUI) openPID() {
	u.pidIn.SetText("")
	u.pages.ShowPage("pid")
	u.pidOpen = true
	u.app.SetFocus(u.pidIn)
}

func (u *tviewUI) refreshStatus() {
	line := statusLine(u.ctrl)
	if u.ctrl.LoggingToFile() {
		line += "   " + i18n.T("ui.logToFile")
	}
	u.status.SetText(" " + line)
}

// Log добавляет блок в лог (потокобезопасно: TextView.Write + SetChangedFunc).
func (u *tviewUI) Log(block string) {
	fmt.Fprint(u.logView, ansiToTview(block))
}

func (u *tviewUI) SetStatus(text string) {
	u.app.QueueUpdateDraw(func() { u.status.SetText(" " + text) })
}

func (u *tviewUI) Run(onQuit func()) {
	if err := u.app.Run(); err != nil {
		fmt.Println(i18n.T("ui.tuiError"), err)
	}
	onQuit()
}

func (u *tviewUI) Stop() { u.app.Stop() }

// center помещает примитив в центр экрана заданного размера.
func center(p tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, height, 1, true).
			AddItem(nil, 0, 1, false), width, 1, true).
		AddItem(nil, 0, 1, false)
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ansiToTview конвертирует наш ограниченный набор ANSI-кодов в теги tview,
// экранируя литеральные '[' в тексте лога (JSON, заголовки и т.п.).
func ansiToTview(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range ansiRE.FindAllStringIndex(s, -1) {
		b.WriteString(tview.Escape(s[last:loc[0]]))
		b.WriteString(ansiTag(s[loc[0]:loc[1]]))
		last = loc[1]
	}
	b.WriteString(tview.Escape(s[last:]))
	return b.String()
}

func ansiTag(code string) string {
	switch code {
	case "\x1b[0m":
		return "[-:-:-]"
	case "\x1b[1m":
		return "[white::b]"
	case "\x1b[2m":
		return "[gray::-]"
	case "\x1b[1;31m":
		return "[red::b]"
	case "\x1b[1;32m":
		return "[green::b]"
	case "\x1b[1;33m":
		return "[yellow::b]"
	case "\x1b[1;35m":
		return "[fuchsia::b]"
	case "\x1b[1;36m":
		return "[aqua::b]"
	}
	return ""
}
