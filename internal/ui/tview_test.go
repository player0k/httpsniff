package ui

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// fakeController — минимальный Controller для тестов UI без пакета proxy.
type fakeController struct {
	pid atomic.Int64
}

func (c *fakeController) FilterPID() int      { return int(c.pid.Load()) }
func (c *fakeController) SetFilterPID(p int)  { c.pid.Store(int64(p)) }
func (c *fakeController) LoggingToFile() bool { return false }

// TestTUISmoke прогоняет TUI на симуляционном экране tcell (без реального
// терминала): построение, рендер лога, ввод PID через 'p', выход по 'q'.
func TestTUISmoke(t *testing.T) {
	ctrl := &fakeController{}
	u := newTview(ctrl)

	sim := tcell.NewSimulationScreen("UTF-8")
	if err := sim.Init(); err != nil {
		t.Fatal(err)
	}
	u.app.SetScreen(sim)

	done := make(chan struct{})
	go u.Run(func() { close(done) })
	time.Sleep(150 * time.Millisecond)

	// Лог с литеральной '[' (должна быть экранирована конвертером).
	u.Log("\033[1;32m▶ REQUEST\033[0m GET https://x/ [array] HTTP/2\n")
	time.Sleep(50 * time.Millisecond)

	// 'p' → ввод "123" → Enter.
	u.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, 'p', tcell.ModNone))
	time.Sleep(50 * time.Millisecond)
	for _, r := range "123" {
		u.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone))
	}
	u.app.QueueEvent(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	time.Sleep(150 * time.Millisecond)

	if got := ctrl.FilterPID(); got != 123 {
		t.Fatalf("ожидался фильтр 123, получено %d", got)
	}

	// 'a' → сброс на все процессы.
	u.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone))
	time.Sleep(100 * time.Millisecond)
	if got := ctrl.FilterPID(); got != 0 {
		t.Fatalf("ожидался фильтр 0 после 'a', получено %d", got)
	}

	// 'q' → выход.
	u.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TUI не завершился по 'q'")
	}
}
