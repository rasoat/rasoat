package core

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Status is vulnerable (a published advisory reaches this version), unsupported (its line gets no more fixes), ok (no
// advisory in this data reaches it) or unknown (we cannot say; Reason tells why).
const (
	Vulnerable  = "vulnerable"
	Unsupported = "unsupported"
	OK          = "ok"
	Unknown     = "unknown"
)

type VerdictAdvisory struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	CVSS     *float64 `json:"cvss"`
	Summary  string   `json:"summary"`
	URL      string   `json:"url"`
}

type Verdict struct {
	Product    string            `json:"product"`
	Version    *string           `json:"version"`
	Status     string            `json:"status"`
	Fix        *string           `json:"fix"`
	NoFix      bool              `json:"noFix"`
	Reason     *string           `json:"reason"`
	Advisories []VerdictAdvisory `json:"advisories"`
}

// ProductNames are the display names of the products a project or site scan judges.
var ProductNames = map[string]string{"next": "Next.js", "wordpress": "WordPress", "node": "Node.js", "php": "PHP", "bun": "Bun"}

func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

func cvss(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func sortWorstFirst(a []VerdictAdvisory) {
	sort.SliceStable(a, func(i, j int) bool {
		if ri, rj := SeverityRank(a[i].Severity), SeverityRank(a[j].Severity); ri != rj {
			return ri < rj
		}
		return cvss(a[i].CVSS) > cvss(a[j].CVSS)
	})
}

func unknown(product string, version *string, reason string) Verdict {
	return Verdict{Product: product, Version: version, Status: Unknown, Reason: &reason, Advisories: []VerdictAdvisory{}}
}

var (
	exactRuntime = NewRe(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	exactNext    = exactRuntime
	wpVersion    = NewRe(`^\d+\.\d+(\.\d+){0,2}$`)
	wpDev        = NewRe(`-.*$`)
	runtimeRe    = NewRe(`^(\d+)\.(\d+)(?:\.(\d+))?(-[0-9A-Za-z.-]+)?$`)
)

// VerdictFor answers for one product at one version. version nil: the version is hidden. today is YYYY-MM-DD.
func VerdictFor(product string, version *string, data *Snapshot, today string) Verdict {
	if version == nil {
		return unknown(product, nil, "version-hidden")
	}
	switch product {
	case "next":
		return nextVerdict(*version, data)
	case "wordpress":
		return wordpressVerdict(*version, data)
	}
	return runtimeVerdict(product, *version, data, today)
}

func parseNextVersion(input string) (string, bool) {
	v := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(input), "v"), "V")
	return v, len(v) <= 40 && exactNext.MatchString(v)
}

func toSemver(r string) string {
	parts := strings.Split(r, ",")
	for i, p := range parts {
		parts[i] = strings.Join(strings.Fields(p), "")
	}
	return strings.Join(parts, " ")
}

func hitRange(version string, a *Advisory) *Range {
	for i := range a.Ranges {
		if Satisfies(version, toSemver(a.Ranges[i].Vulnerable)) {
			return &a.Ranges[i]
		}
	}
	return nil
}

func nextHits(version string, all []Advisory) []*Advisory {
	var hits []*Advisory
	for i := range all {
		if hitRange(version, &all[i]) != nil {
			hits = append(hits, &all[i])
		}
	}
	return hits
}

// nextFix is the lowest version reached by following each hit's patch that no advisory hits; "" when a hit has no patch.
func nextFix(version string, hits []*Advisory, all []Advisory) string {
	fix, open := version, hits
	for guard := 0; fix != "" && len(open) > 0 && guard < 50; guard++ {
		best := ""
		for _, a := range open {
			p := hitRange(fix, a).Patched
			if p == nil {
				return ""
			}
			if best == "" || Order(*p, best) >= 0 {
				best = *p
			}
		}
		fix = best
		open = nextHits(fix, all)
	}
	return fix
}

func nextVerdict(input string, data *Snapshot) Verdict {
	v, ok := parseNextVersion(input)
	if !ok {
		return unknown("next", &input, "version-not-exact")
	}
	hits := nextHits(v, data.Next.Advisories)
	out := Verdict{Product: "next", Version: &v, Status: OK, Advisories: []VerdictAdvisory{}}
	for _, a := range hits {
		out.Advisories = append(out.Advisories, VerdictAdvisory{a.GHSA, a.Severity, a.CVSS, a.Summary, a.URL})
	}
	sortWorstFirst(out.Advisories)
	if len(hits) > 0 {
		out.Status = Vulnerable
		if fix := nextFix(v, hits, data.Next.Advisories); fix != "" {
			out.Fix = &fix
		} else {
			out.NoFix = true
		}
	}
	return out
}

// CompareWp compares WordPress versions, 2 to 4 numeric parts, part by part, missing = 0.
func CompareWp(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		var errX, errY error
		if i < len(pa) {
			x, errX = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, errY = strconv.Atoi(pb[i])
		}
		if errors.Is(errX, strconv.ErrRange) {
			x = math.MaxInt // too long to hold is very large, as in the web app, never zero
		} else if errX != nil {
			continue // NVD writes "*" or a letter in a part: it decides nothing
		}
		if errors.Is(errY, strconv.ErrRange) {
			y = math.MaxInt
		} else if errY != nil {
			continue
		}
		if x != y {
			return cmpInt(x, y)
		}
	}
	return 0
}

func inWpRange(v string, r WpRange) bool {
	if r.Start != nil && *r.Start != "" && CompareWp(v, *r.Start) < 0 {
		return false
	}
	c := CompareWp(v, r.End)
	if r.EndIncluding {
		return c <= 0
	}
	return c < 0
}

func wpBranch(v string) string {
	p := strings.Split(v, ".")
	if len(p) > 2 {
		p = p[:2]
	}
	return strings.Join(p, ".")
}

func wordpressVerdict(version string, data *Snapshot) Verdict {
	release := wpDev.ReplaceAllString(version, "")
	if !wpVersion.MatchString(release) {
		return unknown("wordpress", &version, "version-not-exact")
	}
	status := "unknown"
	if version == release {
		if s, ok := data.WordPress.Stable[version]; ok {
			status = s
		} else if s, ok := data.WordPress.Stable[strings.TrimSuffix(version, ".0")]; ok {
			status = s
		}
	}
	patchedRelease := status == "latest" || status == "outdated"

	// WordPress.org's status is the verdict: older NVD ranges ignore backports and NVD lags recent fixes. CVEs are detail.
	advisories := []VerdictAdvisory{}
	if !patchedRelease {
		for _, c := range data.WordPress.CVEs {
			for _, r := range c.Ranges {
				if inWpRange(release, r) {
					advisories = append(advisories, VerdictAdvisory{c.CVE, c.Severity, c.CVSS, c.Summary, c.URL})
					break
				}
			}
		}
		sortWorstFirst(advisories)
	}

	latest, sameBranch := "", ""
	versions := make([]string, 0, len(data.WordPress.Stable))
	for v := range data.WordPress.Stable {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	for _, v := range versions {
		s := data.WordPress.Stable[v]
		if s == "insecure" {
			continue
		}
		if s == "latest" && latest == "" {
			latest = v
		}
		if wpBranch(v) == wpBranch(release) && (sameBranch == "" || CompareWp(v, sameBranch) >= 0) {
			sameBranch = v
		}
	}
	fix := ""
	if !patchedRelease && !(latest != "" && CompareWp(release, latest) > 0) {
		if sameBranch != "" && CompareWp(sameBranch, release) > 0 {
			fix = sameBranch
		} else {
			fix = latest
		}
	}
	var fixp *string
	if fix != "" {
		fixp = &fix
	}
	switch status {
	case "unknown":
		reason := "not-a-listed-release"
		return Verdict{Product: "wordpress", Version: &version, Status: Unknown, Fix: fixp, Reason: &reason, Advisories: []VerdictAdvisory{}}
	case "insecure":
		return Verdict{Product: "wordpress", Version: &version, Status: Vulnerable, Fix: fixp, NoFix: fixp == nil, Advisories: advisories}
	}
	return Verdict{Product: "wordpress", Version: &version, Status: OK, Advisories: []VerdictAdvisory{}}
}

// NormalizeRuntime: "8.1" becomes "8.1.0", "v20.11.0" becomes "20.11.0"; "" when it is not a version.
func NormalizeRuntime(v string) string {
	s := strings.TrimSpace(v)
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		s = s[1:]
	}
	m := runtimeRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	return m[1] + "." + m[2] + "." + patch + m[4]
}

func branchOf(id, v string) string {
	p := strings.Split(v, ".")
	if id == "php" {
		return strings.Join(p[:min(2, len(p))], ".")
	}
	return p[0]
}

func runtimeVerdict(id, version string, data *Snapshot, today string) Verdict {
	if !exactRuntime.MatchString(version) {
		return unknown(id, &version, "version-not-exact")
	}
	rt := data.Runtimes[id]
	v := NormalizeRuntime(version)
	if v == "" {
		v = version
	}
	var branch *RtBranch
	for i := range rt.Branches {
		if rt.Branches[i].Cycle == branchOf(id, v) {
			branch = &rt.Branches[i]
			break
		}
	}
	if branch == nil {
		return unknown(id, &version, "line-not-listed")
	}
	isEol := func(b *RtBranch) bool { return b.EOL != nil && *b.EOL != "" && *b.EOL <= today }
	eol := isEol(branch)
	upToDate := !eol && Order(v, NormalizeRuntime(branch.Latest)) >= 0
	// The newest release of a supported branch carries every fix the project shipped for it: a source range that still
	// covers it is a data lag, not a vulnerability.
	advisories := []VerdictAdvisory{}
	if !upToDate {
		for _, x := range rt.Vulns {
			if Satisfies(v, x.Vulnerable) && !(x.Patched != nil && *x.Patched != "" && Satisfies(v, *x.Patched)) {
				advisories = append(advisories, VerdictAdvisory{x.ID, x.Severity, x.CVSS, x.Summary, x.URL})
			}
		}
		sortWorstFirst(advisories)
	}
	var supported []*RtBranch
	for i := range rt.Branches {
		if !isEol(&rt.Branches[i]) {
			supported = append(supported, &rt.Branches[i])
		}
	}
	fix := ""
	switch {
	case upToDate:
	case !eol:
		fix = branch.Latest
	default:
		for i := len(supported) - 1; i >= 0 && fix == ""; i-- { // oldest supported line that is newer
			if Order(NormalizeRuntime(supported[i].Latest), v) > 0 {
				fix = supported[i].Latest
			}
		}
		if fix == "" && len(supported) > 0 {
			fix = supported[0].Latest
		}
	}
	status := OK
	if len(advisories) > 0 {
		status = Vulnerable
	} else if eol {
		status = Unsupported
	}
	out := Verdict{Product: id, Version: &version, Status: status, Advisories: advisories}
	if status != OK {
		if fix != "" {
			out.Fix = &fix
		} else {
			out.NoFix = true
		}
	}
	return out
}
