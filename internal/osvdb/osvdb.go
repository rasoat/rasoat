// Package osvdb judges lockfile packages against the reduced OSV files (eco-npm, eco-cargo, eco-go). The CLI asks for an
// ecosystem's file by name and reads only the lines of the packages it has: no package name is ever sent anywhere.
package osvdb

import (
	"bytes"
	"sort"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/deps"
)

// safeID: an advisory id comes from downloaded data and reaches a URL and a terminal.
var safeID = core.NewRe(`^[A-Za-z0-9._-]{1,64}$`)

// AdvisoryURL is where an advisory id is read; false for an id that is not safe to print or link.
func AdvisoryURL(id string) (string, bool) {
	if !safeID.MatchString(id) {
		return "", false
	}
	return "https://osv.dev/vulnerability/" + id, true
}

// File is the data file of an ecosystem.
var File = map[string]string{deps.NPM: "eco-npm", deps.Cargo: "eco-cargo", deps.Go: "eco-go"}

// Range is one affected range of one package: Introduced <= v < Fixed, or <= Last. Both empty: no fix is published.
type Range struct {
	ID, Introduced, Fixed, Last, Severity string
	Aliases                               []string
}

// Pick reads only the lines for the wanted packages. A file can hold a million lines and a project a few hundred packages.
func Pick(lines []byte, wanted map[string]bool) map[string][]Range {
	out := map[string][]Range{}
	for len(lines) > 0 {
		var line []byte
		if end := bytes.IndexByte(lines, '\n'); end < 0 {
			line, lines = lines, nil
		} else {
			line, lines = lines[:end], lines[end+1:]
		}
		tab := bytes.IndexByte(line, '\t')
		if tab <= 0 || !wanted[string(line[:tab])] {
			continue
		}
		f := strings.Split(string(line), "\t")
		if len(f) != 7 {
			continue
		}
		r := Range{ID: f[1], Introduced: f[2], Fixed: f[3], Last: f[4], Severity: f[5]}
		if f[6] != "" {
			r.Aliases = strings.Split(f[6], ",")
		}
		out[f[0]] = append(out[f[0]], r)
	}
	return out
}

// Affects: introduced <= version, and version < fixed (or <= last). A bound that is not a version leaves the range out:
// it cannot be judged, and guessing either way would be a claim.
func (r Range) Affects(version string) bool {
	if r.Introduced != "0" && (!core.ValidVersion(r.Introduced) || core.Order(version, r.Introduced) < 0) {
		return false
	}
	switch {
	case r.Fixed != "":
		return core.ValidVersion(r.Fixed) && core.Order(version, r.Fixed) < 0
	case r.Last != "":
		return core.ValidVersion(r.Last) && core.Order(version, r.Last) <= 0
	}
	return true
}

// Verdict is what the ranges say about one version of one package.
type Verdict struct {
	Hits  []Range // worst first, with an advisory another one names as an alias left out
	Fix   string  // the lowest version above this one that no range reaches
	NoFix bool
}

// Judge: Hits is empty when the version is clean. Fix is the lowest fixed-version boundary, above the version, that no
// range of the package reaches: moving only to the first fix can land in another advisory's range. A range with no fixed
// version (or one that ends at "last affected") has no known next version, so it never produces a candidate, and a
// version it reaches has no Fix at all.
func Judge(version string, ranges []Range) Verdict {
	var hit []Range
	for _, r := range ranges {
		if r.Affects(version) {
			hit = append(hit, r)
		}
	}
	if len(hit) == 0 {
		return Verdict{}
	}
	var candidates []string
	for _, r := range ranges {
		if r.Fixed != "" && core.ValidVersion(r.Fixed) && core.Order(r.Fixed, version) > 0 {
			candidates = append(candidates, r.Fixed)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return core.Order(candidates[i], candidates[j]) < 0 })
	v := Verdict{Hits: dedupe(hit), NoFix: true}
	for _, c := range candidates {
		if !slicesAny(ranges, c) {
			v.Fix, v.NoFix = c, false
			break
		}
	}
	return v
}

func slicesAny(ranges []Range, version string) bool {
	for _, r := range ranges {
		if r.Affects(version) {
			return true
		}
	}
	return false
}

// dedupe orders worst first and drops an advisory that an earlier one names (a GHSA and a GO record of one flaw), so a
// flaw is listed once. The earlier one is the worse-rated, which is the one that carries a severity.
func dedupe(hit []Range) []Range {
	sort.SliceStable(hit, func(i, j int) bool {
		if ri, rj := core.SeverityRank(hit[i].Severity), core.SeverityRank(hit[j].Severity); ri != rj {
			return ri < rj
		}
		return hit[i].ID < hit[j].ID
	})
	seen := map[string]bool{}
	var out []Range
	for _, r := range hit {
		dup := seen[r.ID]
		for _, a := range r.Aliases {
			dup = dup || seen[a]
		}
		seen[r.ID] = true
		for _, a := range r.Aliases {
			seen[a] = true
		}
		if !dup {
			out = append(out, r)
		}
	}
	return out
}
