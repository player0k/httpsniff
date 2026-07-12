package proxy

import (
	"os"
	"testing"

	"httpsniff/internal/ca"
	"httpsniff/internal/procinfo"
)

func TestParentMapAndMatches(t *testing.T) {
	pm := procinfo.ParentMap()
	if len(pm) == 0 {
		t.Skip("ParentMap пуст (не поддерживается на платформе)")
	}
	self := os.Getpid()
	ppid, ok := pm[self]
	if !ok {
		t.Fatalf("нет записи о собственном процессе %d", self)
	}

	authority, err := ca.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := New(authority, 0, 4096, false)

	// Без фильтра — ловим всё.
	if !p.matches(12345) {
		t.Fatal("без фильтра должно совпадать любое")
	}

	// Фильтр = наш PID: сами совпадаем.
	p.SetFilterPID(self)
	if !p.matches(self) {
		t.Fatal("собственный PID должен совпадать")
	}

	// Фильтр = родитель: мы (потомок) должны совпасть по дереву.
	if ppid > 4 {
		p.SetFilterPID(ppid)
		if !p.matches(self) {
			t.Fatalf("потомок %d должен совпасть с корнем-родителем %d", self, ppid)
		}
	}

	// Несуществующий/несвязанный PID не совпадает.
	p.SetFilterPID(self)
	if p.matches(1) {
		t.Fatal("несвязанный PID не должен совпадать")
	}
}
