package i18n

import "testing"

// TestCatalogsComplete проверяет, что каждый язык содержит ровно те же ключи,
// что и английский эталон (без пропусков и без лишних ключей).
func TestCatalogsComplete(t *testing.T) {
	for lang, cat := range catalogs {
		if lang == EN {
			continue
		}
		for key := range en {
			if _, ok := cat[key]; !ok {
				t.Errorf("язык %q: отсутствует ключ %q", lang, key)
			}
		}
		for key := range cat {
			if _, ok := en[key]; !ok {
				t.Errorf("язык %q: лишний ключ %q (нет в эталоне en)", lang, key)
			}
		}
	}
}

// TestFallback проверяет фолбек на английский и на сам ключ.
func TestFallback(t *testing.T) {
	SetLangCode("de")
	if got := T("banner.proxy"); got != "Proxy" {
		t.Fatalf("ожидался немецкий перевод, получено %q", got)
	}
	if got := T("no.such.key"); got != "no.such.key" {
		t.Fatalf("для отсутствующего ключа ожидался сам ключ, получено %q", got)
	}
	SetLangCode("en")
}

// TestResolveRegion проверяет, что региональные коды сводятся к языку.
func TestResolveRegion(t *testing.T) {
	if _, ok := resolve("pt"); !ok {
		t.Fatal("pt должен разрешаться")
	}
	if l, ok := resolve("xx"); ok || l != EN {
		t.Fatalf("неизвестный код должен давать EN/false, получено %q/%v", l, ok)
	}
}

// TestFormatting проверяет подстановку аргументов.
func TestFormatting(t *testing.T) {
	SetLangCode("en")
	if got := T("ui.filterPID", 123); got != "PID 123" {
		t.Fatalf("ожидалось \"PID 123\", получено %q", got)
	}
}
