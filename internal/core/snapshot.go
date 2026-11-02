package core

import (
	"encoding/json"
	"strings"
)

// NOTICES are what anything built on the data must show. They are the program's own, whatever a download says.
var NOTICES = []string{
	"Independent project, not affiliated with Vercel, WordPress, the OpenJS Foundation, The PHP Group or Oven.",
	"Vercel, the Vercel design, Next.js and related marks, designs and logos are trademarks or registered trademarks of Vercel, Inc. or its affiliates in the US and other countries.",
	"This product uses the NVD API but is not endorsed or certified by the NVD.",
	"Next.js advisories: GitHub Advisory Database, CC-BY-4.0. WordPress release status: WordPress.org. Node.js: nodejs/security-wg. Release lines: endoflife.date.",
}

type Range struct {
	Vulnerable string  `json:"vulnerable"`
	Patched    *string `json:"patched"`
}

type Advisory struct {
	GHSA     string   `json:"ghsa"`
	Severity string   `json:"severity"`
	CVSS     *float64 `json:"cvss"`
	Summary  string   `json:"summary"`
	URL      string   `json:"url"`
	Ranges   []Range  `json:"ranges"`
}

type WpRange struct {
	Start        *string `json:"start"`
	End          string  `json:"end"`
	EndIncluding bool    `json:"endIncluding"`
}

type WpCve struct {
	CVE      string    `json:"cve"`
	Severity string    `json:"severity"`
	CVSS     *float64  `json:"cvss"`
	Summary  string    `json:"summary"`
	URL      string    `json:"url"`
	Ranges   []WpRange `json:"ranges"`
}

type WpData struct {
	Stable map[string]string `json:"stable"`
	CVEs   []WpCve           `json:"cves"`
}

type RtBranch struct {
	Cycle  string  `json:"cycle"`
	EOL    *string `json:"eol"`
	Latest string  `json:"latest"`
}

type RtVuln struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	CVSS       *float64 `json:"cvss"`
	Summary    string   `json:"summary"`
	URL        string   `json:"url"`
	Vulnerable string   `json:"vulnerable"`
	Patched    *string  `json:"patched"`
}

type RtData struct {
	ID       string     `json:"id"`
	Fetched  string     `json:"fetched"`
	Branches []RtBranch `json:"branches"`
	Vulns    []RtVuln   `json:"vulns"`
}

type NextRequirement struct {
	V    string `json:"v"`
	Node string `json:"node"`
}

type Requirements struct {
	Next      []NextRequirement `json:"next"`
	WordPress map[string]string `json:"wordpress"`
}

type Snapshot struct {
	Format int    `json:"format"`
	Built  string `json:"built"`
	Next   struct {
		Advisories []Advisory `json:"advisories"`
	} `json:"next"`
	WordPress    WpData            `json:"wordpress"`
	Runtimes     map[string]RtData `json:"runtimes"`
	Requirements Requirements      `json:"requirements"`
}

var (
	dateRe = NewRe(`^\d{4}-\d{2}-\d{2}$`)
)

func isLink(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// ParseSnapshot returns nil when the bytes are not a snapshot this version can read. A verdict from malformed data would
// be worse than none, and a download is untrusted input.
func ParseSnapshot(raw []byte) *Snapshot {
	var s Snapshot
	if json.Unmarshal(raw, &s) != nil || s.Format != 1 || !dateRe.MatchString(s.Built) || !s.valid() {
		return nil
	}
	return &s
}

func (s *Snapshot) valid() bool {
	for _, a := range s.Next.Advisories {
		if a.GHSA == "" || a.Severity == "" || !isLink(a.URL) || a.Ranges == nil {
			return false
		}
		for _, r := range a.Ranges {
			if r.Vulnerable == "" {
				return false
			}
		}
	}
	if s.Next.Advisories == nil || s.WordPress.Stable == nil || s.WordPress.CVEs == nil {
		return false
	}
	for _, c := range s.WordPress.CVEs {
		if c.CVE == "" || c.Severity == "" || !isLink(c.URL) || c.Ranges == nil {
			return false
		}
		for _, r := range c.Ranges {
			if r.End == "" {
				return false
			}
		}
	}
	for _, id := range []string{"node", "php", "bun"} {
		r, ok := s.Runtimes[id]
		if !ok || r.ID == "" || !dateRe.MatchString(r.Fetched) || r.Branches == nil || r.Vulns == nil {
			return false
		}
		for _, b := range r.Branches {
			if b.Cycle == "" || b.Latest == "" {
				return false
			}
		}
		for _, v := range r.Vulns {
			if v.ID == "" || v.Severity == "" || !isLink(v.URL) || v.Vulnerable == "" {
				return false
			}
		}
	}
	return s.Requirements.Next != nil && s.Requirements.WordPress != nil
}

// Counts are the records per dataset, in a fixed order.
func (s *Snapshot) Counts() []int {
	return []int{len(s.Next.Advisories), len(s.WordPress.CVEs), len(s.Runtimes["node"].Vulns), len(s.Runtimes["php"].Vulns), len(s.Runtimes["bun"].Vulns)}
}

// KeepsCoverage is false when a newer-looking snapshot lost so many records that it would call vulnerable versions clean.
func KeepsCoverage(candidate, floor []int) bool {
	for i := range floor {
		if float64(candidate[i]) < float64(floor[i])*0.9 {
			return false
		}
	}
	return true
}
