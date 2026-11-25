package core

import (
	"strings"
	"testing"
	"unicode"
)

func TestUntrusted(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "next 14.2.3", "next 14.2.3"},
		{"esc sequence", "\x1b[31mX\x1b[0m", "[31mX[0m"},
		{"osc", "a\x1b]8;;http://x\x07b", "a]8;;http://xb"},
		{"c1 csi", "a\u009b31mb", "a31mb"},
		{"bidi override", "evil\u202Efdp.exe", "evilfdp.exe"},
		{"bidi isolate", "a\u2066b\u2069c", "abc"},
		{"zero width", "ne\u200Bxt", "next"},
		{"bom", "\uFEFFnext", "next"},
		{"crlf is one space", "a\r\nb", "a b"},
		{"newline then fake line", "x\nVULNERABLE  next 99.0.0", "x VULNERABLE  next 99.0.0"},
		{"tab and vtab", "a\t\v\fb", "a b"},
		{"line separator", "a\u2028b", "a b"},
		{"trim", " \n a \n ", "a"},
		{"invalid bytes", "a\xff\xfeb", "a\uFFFDb"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := Untrusted(c.in, 200); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestUntrustedCapsRunes(t *testing.T) {
	got := Untrusted(strings.Repeat("é", 10000), 200)
	if r := []rune(got); len(r) != 203 || !strings.HasSuffix(got, "...") {
		t.Errorf("%d runes", len(r))
	}
	if got := Untrusted("abc", 3); got != "abc" {
		t.Error(got)
	}
	for _, r := range Untrusted("\x1b\u202e"+strings.Repeat("x", 500), 10) {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("%U", r)
		}
	}
}

type sample struct {
	Name  string
	Ptr   *string
	List  []string
	Map   map[string]string
	Long  string `untrusted:"500"`
	Inner struct{ S string }
	Any   any
	n     string
}

func TestSanitizeTreeRewritesEveryStringShape(t *testing.T) {
	bad := "a\x1b[0m\nb"
	p := bad
	s := sample{Name: bad, Ptr: &p, List: []string{bad}, Map: map[string]string{"k": bad}, Long: strings.Repeat("x", 400), n: bad, Any: bad}
	s.Inner.S = bad
	SanitizeTree(&s)
	for _, got := range []string{s.Name, *s.Ptr, s.List[0], s.Map["k"], s.Inner.S, s.Any.(string)} {
		if got != "a[0m b" {
			t.Errorf("%q", got)
		}
	}
	if len([]rune(s.Long)) != 400 {
		t.Error("a tagged field must keep its length")
	}
	if s.n != bad {
		t.Error("an unexported field is not touched")
	}
	s.Name = strings.Repeat("y", 300)
	SanitizeTree(&s)
	if len([]rune(s.Name)) != 203 {
		t.Error("default cap")
	}
}
