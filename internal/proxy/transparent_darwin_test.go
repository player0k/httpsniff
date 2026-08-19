//go:build darwin

package proxy

import (
	"strings"
	"testing"
	"unsafe"
)

func TestTransparentPFRules(t *testing.T) {
	rules := transparentPFRules(8889, 0)
	for _, want := range []string{
		"rdr pass on lo0",
		"port { 80, 443 } -> 127.0.0.1 port 8889",
		"pass out route-to lo0",
		"user != 0",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("rules do not contain %q:\n%s", want, rules)
		}
	}
}

func TestPFTokenRegexp(t *testing.T) {
	m := pfTokenRE.FindStringSubmatch("pf enabled\nToken : 1234567890\n")
	if len(m) != 2 || m[1] != "1234567890" {
		t.Fatalf("unexpected match: %#v", m)
	}
}

func TestPfiocNatlookABI(t *testing.T) {
	if got := unsafe.Sizeof(pfiocNatlook{}); got != 84 {
		t.Fatalf("pfioc_natlook size = %d, want 84", got)
	}
	if diocNatlook != 0xc0544417 {
		t.Fatalf("DIOCNATLOOK = %#x, want %#x", diocNatlook, uintptr(0xc0544417))
	}
}
