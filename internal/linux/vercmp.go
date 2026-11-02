// Package linux judges a Linux machine from its own files: which distro release and kernel it runs, which installed
// packages have a published fix it lacks. It runs no command. Each comparator below is tested on real version pairs
// against the tool that owns the format: dpkg, rpm, apk.
package linux

import (
	"strconv"
	"strings"
)

// Compare compares two versions of a family: deb, rpm or apk.
func Compare(family, a, b string) int {
	switch family {
	case "deb":
		return CompareDeb(a, b)
	case "rpm":
		return CompareRPM(a, b)
	}
	return CompareApk(a, b)
}

func splitEpoch(v string) (int, string) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			return n, v[i+1:]
		}
	}
	return 0, v
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// compareDigits compares two digit strings as numbers of any length.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}

// CompareDeb follows Debian Policy 5.6.12: epoch, upstream version, revision.
func CompareDeb(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if ea != eb {
		return sign(ea - eb)
	}
	ua, va := cutLast(ra, '-')
	ub, vb := cutLast(rb, '-')
	if c := debPart(ua, ub); c != 0 {
		return c
	}
	return debPart(va, vb)
}

func cutLast(s string, sep byte) (string, string) {
	if i := strings.LastIndexByte(s, sep); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0 || isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	}
	return int(c) + 256
}

func debPart(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			if x, y := debOrder(at(a, i)), debOrder(at(b, j)); x != y {
				return sign(x - y)
			}
			i++
			j++
		}
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareDigits(a[si:min(i, len(a))], b[sj:min(j, len(b))]); c != 0 {
			return c
		}
	}
	return 0
}

// CompareRPM compares [epoch:]version[-release] as rpm does. A release absent on one side counts as older.
func CompareRPM(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if ea != eb {
		return sign(ea - eb)
	}
	va, rela := cutLast(ra, '-')
	vb, relb := cutLast(rb, '-')
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(rela, relb)
}

func rpmSep(c byte) bool { return !isDigit(c) && !isAlpha(c) && c != '~' && c != '^' }

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && rpmSep(a[i]) {
			i++
		}
		for j < len(b) && rpmSep(b[j]) {
			j++
		}
		atA, atB := i < len(a), j < len(b)
		if (atA && a[i] == '~') || (atB && b[j] == '~') {
			if !atA || a[i] != '~' {
				return 1
			}
			if !atB || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if (atA && a[i] == '^') || (atB && b[j] == '^') {
			if !atA {
				return -1
			}
			if !atB {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if !atA || !atB {
			break
		}
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		if sj == j { // the two segments are of different kinds: a number is newer
			if numeric {
				return 1
			}
			return -1
		}
		var c int
		if numeric {
			c = compareDigits(a[si:i], b[sj:j])
		} else {
			c = sign(strings.Compare(a[si:i], b[sj:j]))
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}

var apkSuffix = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

type apkToken struct {
	kind int // 0 number, 1 letter, 2 suffix, 3 suffix number, 4 revision, 5 end
	text string
	rank int // for a number with leading zeros: minus how many
}

func apkTokens(v string) []apkToken {
	var out []apkToken
	i := 0
	digits := func() string {
		s := i
		for i < len(v) && isDigit(v[i]) {
			i++
		}
		return v[s:i]
	}
	for i < len(v) {
		c := v[i]
		switch {
		case isDigit(c):
			// After a dot, leading zeros are a token of their own: 1.001 is below 1.01 is below 1.1.
			if i > 0 && v[i-1] == '.' && c == '0' {
				s := i
				for i < len(v) && v[i] == '0' {
					i++
				}
				out = append(out, apkToken{kind: 0, rank: s - i})
				if i == len(v) || !isDigit(v[i]) {
					continue
				}
			}
			out = append(out, apkToken{kind: 0, text: digits()})
		case c == '.':
			i++
		case c == '_':
			s := i + 1
			i++
			for i < len(v) && isAlpha(v[i]) {
				i++
			}
			out = append(out, apkToken{kind: 2, rank: apkSuffix[v[s:i]]})
			if i < len(v) && isDigit(v[i]) {
				out = append(out, apkToken{kind: 3, text: digits()})
			}
		case c == '-' && i+1 < len(v) && v[i+1] == 'r':
			i += 2
			out = append(out, apkToken{kind: 4, text: digits()})
		case isAlpha(c):
			out = append(out, apkToken{kind: 1, rank: int(c)})
			i++
		default:
			i++
		}
	}
	return out
}

// CompareApk follows apk-tools: numbers, one letter, suffixes (_alpha to _rc sort before none, _cvs to _p after), -rN.
func CompareApk(a, b string) int {
	ta, tb := apkTokens(a), apkTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		var x, y apkToken
		x.kind, y.kind = 5, 5
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		if x.kind == y.kind {
			switch x.kind {
			case 0:
				c := 0
				switch {
				case x.rank != 0 || y.rank != 0:
					c = sign(x.rank - y.rank)
					if x.rank == 0 && x.text != "" {
						c = 1
					}
					if y.rank == 0 && y.text != "" {
						c = -1
					}
				default:
					c = compareDigits(x.text, y.text)
				}
				if c != 0 {
					return c
				}
			case 1, 2:
				if x.rank != y.rank {
					return sign(x.rank - y.rank)
				}
			case 3, 4:
				if c := compareDigits(x.text, y.text); c != 0 {
					return c
				}
			}
			continue
		}
		rank := func(t apkToken) int {
			switch {
			case t.kind == 2 && t.rank < 0:
				return -1 // _rc and friends are older than the end of the string
			case t.kind == 5:
				return 0
			}
			return 5 - t.kind // whichever string goes on with an earlier kind of token is newer
		}
		return sign(rank(x) - rank(y))
	}
	return 0
}
