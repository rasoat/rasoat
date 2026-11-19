package images

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
)

// Reasons a verdict here can carry; report/render.go words each in both languages.
const (
	ReasonUnpinned   = "image-tag-unpinned"
	ReasonNoAdvisory = "no-advisory-data"
	ReasonDistro     = "distro-release-supported"
	ReasonNoLines    = "line-data-not-available"
	ReasonNotExact   = "version-not-exact"
	ReasonNotListed  = "line-not-listed"
)

// Release is one release line of a product, as the linux index carries it (linux.Line has the same fields; this package
// does not import it, so the index builder can share this package's family table without the program's embedded data).
type Release struct {
	Cycle    string
	EOL      string // YYYY-MM-DD; "" while no end is set
	Latest   string
	Extended string
}

// EndedLine is the EOL of a line a product's own advisory list says gets no more releases, when it gives no date.
const EndedLine = "ended"

// compare orders dotted numeric versions part by part, missing = 0: 16.4 < 16.16, 24.8.4.13 > 24.8.
func compare(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// hasPrefix: the cycle's parts are the first parts of the version, compared as text so 22.04 is not 22.4.
func hasPrefix(version, cycle string) bool {
	v, c := strings.Split(version, "."), strings.Split(cycle, ".")
	return len(c) <= len(v) && slices.Equal(v[:len(c)], c)
}

// lineFor is the release line a tag lives on: the longest cycle the version starts with (16.4 lives on 16), else the
// newest cycle that starts with the version (a tag `7` floats to the newest 7.x).
func lineFor(version string, lines []Release) (Release, bool) {
	best, found := Release{}, false
	for _, l := range lines {
		if hasPrefix(version, l.Cycle) && (!found || len(l.Cycle) > len(best.Cycle)) {
			best, found = l, true
		}
	}
	if found {
		return best, true
	}
	for _, l := range lines {
		if hasPrefix(l.Cycle, version) && (!found || compare(l.Cycle, best.Cycle) > 0) {
			best, found = l, true
		}
	}
	return best, found
}

func ended(l Release, today string) bool {
	return l.EOL == EndedLine || (l.EOL != "" && l.EOL <= today)
}

// fixFor is the latest release of the nearest supported line newer than this one, else of the newest supported line.
func fixFor(l Release, lines []Release, today string) string {
	var live []Release
	for _, x := range lines {
		if !ended(x, today) {
			live = append(live, x)
		}
	}
	slices.SortFunc(live, func(a, b Release) int { return compare(a.Cycle, b.Cycle) })
	for _, x := range live {
		if compare(x.Cycle, l.Cycle) > 0 {
			return x.Latest
		}
	}
	if len(live) > 0 {
		return live[len(live)-1].Latest
	}
	return ""
}

func unknown(r Ref, reason string) core.Verdict {
	v := &r.Version
	if r.Version == "" {
		v = nil
	}
	return core.Verdict{Product: r.Family.ID, Version: v, Status: core.Unknown, Reason: &reason, Advisories: []core.VerdictAdvisory{}}
}

// Judge answers for a family the CLI has no advisories for, from its release lines alone. how is a sentence for a person
// ("" when there is none). It never says ok: this data knows when a line ends, not which flaws a release has.
func Judge(r Ref, lines map[string][]Release, today string) (v core.Verdict, how string) {
	if r.Kind == Unpinned {
		return unknown(r, ReasonUnpinned), ""
	}
	ls := lines[r.Family.ID]
	if len(ls) == 0 {
		if r.Family.NoEOL { // recognised, with no list of releases and no advisories to read: said plainly, never ok
			return unknown(r, ReasonNoAdvisory), fmt.Sprintf("no advisory data and no release-line data for %s: it is recognised, and nothing about this version is judged", Name(r.Family.ID))
		}
		return unknown(r, ReasonNoLines), ""
	}
	l, ok := lineFor(r.Version, ls)
	if !ok {
		return unknown(r, ReasonNotListed), ""
	}
	name := Name(r.Family.ID)
	if ended(l, today) {
		v = unknown(r, "")
		v.Status, v.Reason = core.Unsupported, nil
		if fix := fixFor(l, ls, today); fix != "" {
			v.Fix = &fix
		} else {
			v.NoFix = true
		}
		if l.EOL == EndedLine {
			return v, fmt.Sprintf("%s line %s has ended", name, l.Cycle)
		}
		return v, fmt.Sprintf("%s line %s ended %s", name, l.Cycle, l.EOL)
	}
	switch {
	case r.Kind == Line && r.Family.Distro:
		return unknown(r, ReasonDistro), fmt.Sprintf("%s %s is supported; latest is %s", name, l.Cycle, l.Latest)
	case r.Kind == Line:
		return unknown(r, ReasonNotExact), fmt.Sprintf("line %s is supported; its latest is %s", l.Cycle, l.Latest)
	}
	v = unknown(r, ReasonNoAdvisory)
	if l.Latest != "" && compare(r.Version, l.Latest) < 0 {
		v.Fix = &l.Latest
	}
	return v, fmt.Sprintf("no advisory data for %s; line %s latest is %s", name, l.Cycle, l.Latest)
}
