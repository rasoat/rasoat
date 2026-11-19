package core

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// One shape and one verdict for the advisory list of a web server or proxy (nginx, Apache httpd, and the products after
// them), judged against one exact upstream version: an image tag, a vendor package, a source build. This is
// packages/core/src/server.ts, rule for rule; scripts/cli/conformance.ts holds the two together. A distro package is never
// judged here: distros backport fixes under their own version strings. Each product's own words (severity, ranges) are
// mapped once, when the snapshot is built; nothing here knows a product.

// ServerAdvisory is one entry of a list. Title and URL are for display; the verdict does not read them.
type ServerAdvisory struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Severity string `json:"severity"` // critical, high, medium, low or none
	// Vulnerable: `2.4.17-2.4.68` (inclusive), `2.4.30-<2.4.66` (upper bound excluded), one version, or `all`.
	Vulnerable []string `json:"vulnerable"`
	// Fixed: the releases that fix it, one per line; empty when no release fixes it.
	Fixed []string `json:"fixed"`
}

// ServerLine is one release line (`2.4`) and whether it gets no more releases.
type ServerLine struct {
	Line   string `json:"line"`
	EOL    bool   `json:"eol"`
	Latest string `json:"latest"`
}

type ServerAdvisories struct {
	Product string `json:"product"` // the family id: the key of Snapshot.Servers
	Source  string `json:"source"`  // the page the list comes from
	// LineParts: numbers that name a release line (2 for `2.4`). An exact version has one more.
	LineParts  int              `json:"lineParts"`
	Lines      []ServerLine     `json:"lines"`
	Fetched    string           `json:"fetched"`
	Advisories []ServerAdvisory `json:"advisories"`
}

type ServerHit struct {
	ID, Severity, Title, URL string
}

type ServerResult struct {
	Status string // OK or Vulnerable
	Hits   []ServerHit
	Line   string // `2.4`
	EOL    bool   // the line gets no more releases: OK only means no advisory is listed for it
	Fix    string // "" when ok, or when a hit has no fixed release
}

type sv []int

var serverSeverities = []string{"critical", "high", "medium", "low", "unknown", "none"}
var serverNumber = regexp.MustCompile(`^\d+$`)

// parseServer reads an exact version of n numbers. It refuses anything else: a tag such as `alpine` or `2.4` is never guessed at.
func parseServer(s string, n int) (sv, bool) {
	fields := strings.Split(strings.TrimSpace(s), ".")
	if len(fields) != n {
		return nil, false
	}
	v := make(sv, n)
	for i, f := range fields {
		x, err := strconv.Atoi(f)
		if err != nil || !serverNumber.MatchString(f) {
			return nil, false
		}
		v[i] = x
	}
	return v, true
}

func (a sv) cmp(b sv) int          { return slices.Compare(a, b) }
func (a sv) line(parts int) string { return a[:parts].String() }
func (a sv) String() string {
	out := make([]string, len(a))
	for i, x := range a {
		out[i] = strconv.Itoa(x)
	}
	return strings.Join(out, ".")
}

// serverRange reads `all`, `lo`, `lo-hi` or `lo-<hi` (hi excluded).
func serverRange(r string, n int) (lo, hi sv, all, excl, ok bool) {
	if r == "all" {
		return nil, nil, true, false, true
	}
	parts := strings.Split(r, "-")
	if len(parts) > 2 {
		return nil, nil, false, false, false
	}
	hiText := parts[0]
	if len(parts) == 2 {
		hiText = parts[1]
		if rest, cut := strings.CutPrefix(hiText, "<"); cut {
			hiText, excl = rest, true
		}
	}
	lo, ok1 := parseServer(parts[0], n)
	hi, ok2 := parseServer(hiText, n)
	return lo, hi, false, excl, ok1 && ok2
}

func inServerRange(v sv, r string, n int) bool {
	lo, hi, all, excl, _ := serverRange(r, n)
	if all {
		return true
	}
	c := v.cmp(hi)
	return v.cmp(lo) >= 0 && (c < 0 || (!excl && c == 0))
}

func serverFixes(a *ServerAdvisory, n int) []sv {
	out := make([]sv, 0, len(a.Fixed))
	for _, f := range a.Fixed {
		v, _ := parseServer(f, n)
		out = append(out, v)
	}
	return out
}

// highest is the index of the largest; on a tie the first, as the TypeScript reduce does.
func highest(bs []sv) int {
	top := 0
	for i, b := range bs {
		if b.cmp(bs[top]) > 0 {
			top = i
		}
	}
	return top
}

// ValidServer: every line, range and fixed release of the list reads, and each fixed release is on a known line. A list that
// does not is not used: a verdict from half-read data would be worse than none.
func ValidServer(d *ServerAdvisories) bool {
	n := d.LineParts + 1
	if d.Product == "" || !isLink(d.Source) || d.LineParts < 1 || len(d.Lines) == 0 {
		return false
	}
	known := map[string]bool{}
	for _, l := range d.Lines {
		if _, ok := parseServer(l.Line+".0", n); !ok {
			return false
		}
		known[l.Line] = true
	}
	for i := range d.Advisories {
		a := &d.Advisories[i]
		if a.ID == "" || !slices.Contains(serverSeverities, a.Severity) || !isLink(a.URL) || a.Vulnerable == nil || a.Fixed == nil {
			return false
		}
		for _, r := range a.Vulnerable {
			if _, _, _, _, ok := serverRange(r, n); !ok {
				return false
			}
		}
		for _, f := range a.Fixed {
			v, ok := parseServer(f, n)
			if !ok || !known[v.line(d.LineParts)] {
				return false
			}
		}
	}
	return true
}

// ServerVerdict judges one exact upstream version. ok is false when version is not exact, or its line is not in the data
// (nothing is said then).
func ServerVerdict(version string, d *ServerAdvisories) (res ServerResult, ok bool) {
	n := d.LineParts + 1
	v, ok := parseServer(version, n)
	if !ok {
		return ServerResult{}, false
	}
	line := v.line(d.LineParts)
	li := slices.IndexFunc(d.Lines, func(l ServerLine) bool { return l.Line == line })
	if li < 0 {
		return ServerResult{}, false
	}
	eol := d.Lines[li].EOL
	// Left out: severity "none" (a listed issue that is not a flaw of the product itself).
	var hits []*ServerAdvisory
	for i := range d.Advisories {
		a := &d.Advisories[i]
		// Fixed for v: a release of its own line that is at or below it.
		if a.Severity == "none" || slices.ContainsFunc(serverFixes(a, n), func(f sv) bool { return f.line(d.LineParts) == line && v.cmp(f) >= 0 }) {
			continue
		}
		for _, r := range a.Vulnerable {
			if inServerRange(v, r, n) {
				hits = append(hits, a)
				break
			}
		}
	}
	if len(hits) == 0 {
		return ServerResult{Status: OK, Line: line, EOL: eol}, true
	}
	res = ServerResult{Status: Vulnerable, Line: line, EOL: eol}
	for _, a := range hits {
		res.Hits = append(res.Hits, ServerHit{a.ID, a.Severity, a.Title, a.URL})
	}
	for _, a := range hits {
		if len(a.Fixed) == 0 {
			return res, true // an advisory with no fixed release: no version clears it
		}
	}
	// The lowest release on the reader's line that clears every hit, if each hit has a fix there; otherwise (an end-of-life
	// line, or a hit fixed only elsewhere) each hit's newest fix, the largest of them.
	var onLine []sv
	every := true
	for _, a := range hits {
		var here []sv
		for _, f := range serverFixes(a, n) {
			if f.line(d.LineParts) == line {
				here = append(here, f)
			}
		}
		if len(here) == 0 {
			every = false
			break
		}
		onLine = append(onLine, here[highest(here)])
	}
	var fix sv
	if every {
		fix = onLine[highest(onLine)]
	} else {
		var tops []sv
		for _, a := range hits {
			fs := serverFixes(a, n)
			tops = append(tops, fs[highest(fs)])
		}
		fix = tops[highest(tops)]
	}
	// The fix must itself be clean: an advisory that starts above version can still reach it. Terminates: each step is higher.
	again, _ := ServerVerdict(fix.String(), d)
	switch {
	case again.Status == OK:
		res.Fix = fix.String()
	case again.Fix != "":
		res.Fix = again.Fix
	}
	return res, true
}
