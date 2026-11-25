package core

import (
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// Untrusted makes text from a scanned project, a package index or a download safe to show: to a terminal, a person or
// a model. Invalid UTF-8 becomes U+FFFD; control and format runes (ESC, C1, bidi overrides, zero-width, BOM) are
// dropped; line breaks and tabs become one space, so a name can never start a line of its own; the rest is cut to max
// runes with "..." appended.
func Untrusted(s string, max int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	n := 0
	space := func() bool { return b.Len() == 0 || strings.HasSuffix(b.String(), " ") }
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) && r != ' ' && (unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)):
			if space() {
				continue
			}
			r = ' '
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if n == max+1 {
			break // enough to know it is cut
		}
		b.WriteRune(r)
		n++
	}
	out := strings.TrimSpace(b.String())
	if r := []rune(out); len(r) > max {
		return strings.TrimSpace(string(r[:max])) + "..."
	}
	return out
}

// DefaultUntrusted is the cap, in runes, of a string that has no `untrusted:"N"` tag.
const DefaultUntrusted = 200

// SanitizeTree rewrites every string reachable from v (a pointer to a struct, slice or map) with Untrusted: the one pass
// over a finished document, before any renderer, JSON writer, agent channel or hook reads it. A field that needs more
// than DefaultUntrusted runes (a path, a command, an advisory summary) carries `untrusted:"N"`; a tag on a slice or
// pointer field applies to what it holds. Map keys and unexported fields are left alone.
func SanitizeTree(v any) {
	walkUntrusted(reflect.ValueOf(v), DefaultUntrusted)
}

func walkUntrusted(v reflect.Value, max int) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			if v.Kind() == reflect.Interface {
				// an interface's value is not addressable: copy, rewrite, store back
				c := reflect.New(v.Elem().Type()).Elem()
				c.Set(v.Elem())
				walkUntrusted(c, max)
				if v.CanSet() {
					v.Set(c)
				}
				return
			}
			walkUntrusted(v.Elem(), max)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(Untrusted(v.String(), max))
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			m := max
			if tag, ok := f.Tag.Lookup("untrusted"); ok {
				if n, err := strconv.Atoi(tag); err == nil && n > 0 {
					m = n
				}
			}
			walkUntrusted(v.Field(i), m)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkUntrusted(v.Index(i), max)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			e := v.MapIndex(k)
			if e.Kind() != reflect.String && e.Kind() != reflect.Struct && e.Kind() != reflect.Pointer && e.Kind() != reflect.Slice && e.Kind() != reflect.Interface {
				continue
			}
			c := reflect.New(e.Type()).Elem()
			c.Set(e)
			walkUntrusted(c, max)
			v.SetMapIndex(k, c)
		}
	}
}
