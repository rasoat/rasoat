// Package core holds what a verdict needs: versions, the advisory snapshot, and one answer per product per version.
// It does no input or output. The web app has the same rules in TypeScript; testdata/conformance.json.gz, generated from
// that code, is what the tests here must equal.
package core

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type semver struct {
	major, minor, patch int
	pre                 []string
}

// parseSemver is by hand: a scan asks it hundreds of thousands of times, once per version in every range of the data.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	if s != "" && (s[0] == 'v' || s[0] == 'V' || s[0] == '=') {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !validIdents(s[i+1:]) {
			return semver{}, false
		}
		s = s[:i]
	}
	var v semver
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if !validIdents(s[i+1:]) {
			return semver{}, false
		}
		v.pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	a, rest, ok1 := strings.Cut(s, ".")
	b, c, ok2 := strings.Cut(rest, ".")
	if !ok1 || !ok2 || !isNum(a) || !isNum(b) || !isNum(c) {
		return semver{}, false
	}
	v.major, v.minor, v.patch = atoi(a), atoi(b), atoi(c)
	return v, true
}

func isNum(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func validIdents(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-') {
			return false
		}
	}
	return s != ""
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return math.MaxInt // a number too long to hold sorts as very large, never as zero
	}
	return n
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (a semver) cmp(b semver) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := cmpIdent(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a.pre), len(b.pre))
}

func cmpIdent(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return cmpInt(an, bn)
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// Order compares two versions: negative, zero, positive. A string that is not a version sorts first.
func Order(a, b string) int {
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	switch {
	case !oka && !okb:
		return 0
	case !oka:
		return -1
	case !okb:
		return 1
	}
	return va.cmp(vb)
}

type comparator struct {
	op string
	v  semver
}

func splitOp(tok string) (string, string) {
	for _, op := range [...]string{">=", "<=", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(tok, op) {
			return op, tok[len(op):]
		}
	}
	return "", tok
}

func isWild(s string) bool { return s == "" || s == "x" || s == "X" || s == "*" }

// expand turns one npm range token into plain comparators; false when it cannot be read.
func expand(tok string) ([]comparator, bool) {
	op, rest := splitOp(tok)
	rest = strings.TrimLeft(rest, " \t")
	if rest != "" && (rest[0] == 'v' || rest[0] == 'V') {
		rest = rest[1:]
	}
	var pre []string
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		if !validIdents(rest[i+1:]) {
			return nil, false
		}
		pre = strings.Split(rest[i+1:], ".")
		rest = rest[:i]
	}
	parts := strings.Split(rest, ".")
	if len(parts) > 3 {
		return nil, false
	}
	m := [5]string{}
	for i, p := range parts {
		if !isNum(p) && !(p == "x" || p == "X" || p == "*") {
			return nil, false
		}
		m[i+2] = p
	}
	if isWild(m[2]) {
		if op == "<" || op == ">" {
			return nil, true // matches nothing in npm; rejected by the caller through an impossible pair
		}
		return []comparator{}, true
	}
	maj, minWild, patWild := atoi(m[2]), isWild(m[3]), isWild(m[4])
	minr, pat := 0, 0
	if !minWild {
		minr = atoi(m[3])
	}
	if !patWild {
		pat = atoi(m[4])
	}
	low := semver{major: maj, minor: minr, patch: pat, pre: pre}
	floor := []string{"0"} // <X.0.0-0 excludes prereleases of the next line
	switch op {
	case "^":
		var up semver
		switch {
		case maj > 0 || minWild:
			up = semver{major: maj + 1, pre: floor}
		case minr > 0 || patWild:
			up = semver{minor: minr + 1, pre: floor}
		default:
			up = semver{patch: pat + 1, pre: floor}
		}
		return []comparator{{">=", low}, {"<", up}}, true
	case "~":
		if minWild {
			return []comparator{{">=", low}, {"<", semver{major: maj + 1, pre: floor}}}, true
		}
		return []comparator{{">=", low}, {"<", semver{major: maj, minor: minr + 1, pre: floor}}}, true
	}
	if minWild || patWild {
		up := semver{major: maj + 1, pre: floor}
		if !minWild {
			up = semver{major: maj, minor: minr + 1, pre: floor}
		}
		switch op {
		case "", "=":
			return []comparator{{">=", low}, {"<", up}}, true
		case ">=":
			return []comparator{{">=", low}}, true
		case "<":
			return []comparator{{"<", low}}, true
		case ">":
			return []comparator{{">=", semver{major: up.major, minor: up.minor}}}, true
		case "<=":
			return []comparator{{"<", up}}, true
		}
	}
	if op == "" {
		op = "="
	}
	return []comparator{{op, low}}, true
}

func (c comparator) holds(v semver) bool {
	d := v.cmp(c.v)
	switch c.op {
	case ">=":
		return d >= 0
	case "<=":
		return d <= 0
	case ">":
		return d > 0
	case "<":
		return d < 0
	}
	return d == 0
}

// Satisfies follows npm semver, prereleases included: a prerelease satisfies a range only if a comparator in the same
// alternative names a prerelease of the same x.y.z. The advisory ranges are written for that rule.
func Satisfies(version, rng string) bool {
	v, ok := parseSemver(version)
	if !ok {
		return false
	}
	for _, alt := range parseRange(rng) {
		if alt.holds(v) {
			return true
		}
	}
	return false
}

type alternative []comparator

var parsedRanges sync.Map // range text to []alternative: the same few ranges are asked about for every version

func parseRange(rng string) []alternative {
	if got, ok := parsedRanges.Load(rng); ok {
		return got.([]alternative)
	}
	var out []alternative
	for _, alt := range strings.Split(rng, "||") {
		var set alternative
		good := true
		for _, tok := range strings.Fields(joinOps(alt)) {
			cs, ok := expand(tok)
			if !ok || cs == nil {
				good = false
				break
			}
			set = append(set, cs...)
		}
		if good {
			out = append(out, set)
		}
	}
	parsedRanges.Store(rng, out)
	return out
}

// joinOps closes the space after an operator: ">= 20.0.0" is one token.
func joinOps(alt string) string {
	f := strings.Fields(alt)
	for i := 0; i < len(f)-1; i++ {
		switch f[i] {
		case ">=", "<=", ">", "<", "=", "^", "~":
			f[i+1] = f[i] + f[i+1]
			f[i] = ""
		}
	}
	return strings.Join(f, " ")
}

func (set alternative) holds(v semver) bool {
	for _, c := range set {
		if !c.holds(v) {
			return false
		}
	}
	if len(v.pre) == 0 {
		return true
	}
	for _, c := range set {
		if len(c.v.pre) > 0 && c.v.major == v.major && c.v.minor == v.minor && c.v.patch == v.patch {
			return true
		}
	}
	return false
}

// Re is a regexp compiled on first use. A run touches few of them, and compiling all at start-up costs milliseconds on
// every run, which is most of what a run's start costs.
type Re struct {
	pattern string
	once    sync.Once
	re      *regexp.Regexp
}

func NewRe(pattern string) *Re { return &Re{pattern: pattern} }

func (r *Re) get() *regexp.Regexp {
	r.once.Do(func() { r.re = regexp.MustCompile(r.pattern) })
	return r.re
}

func (r *Re) MatchString(s string) bool              { return r.get().MatchString(s) }
func (r *Re) FindString(s string) string             { return r.get().FindString(s) }
func (r *Re) FindStringSubmatch(s string) []string   { return r.get().FindStringSubmatch(s) }
func (r *Re) FindAllString(s string, n int) []string { return r.get().FindAllString(s, n) }
func (r *Re) ReplaceAllString(s, repl string) string { return r.get().ReplaceAllString(s, repl) }
func (r *Re) FindAllStringSubmatch(s string, n int) [][]string {
	return r.get().FindAllStringSubmatch(s, n)
}
func (r *Re) ReplaceAllStringFunc(s string, f func(string) string) string {
	return r.get().ReplaceAllStringFunc(s, f)
}
