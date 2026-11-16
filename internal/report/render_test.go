package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
)

func pkgResult(i int, advisories int) Result {
	v := "1.0.0"
	fix := "2.0.0"
	r := Result{Verdict: core.Verdict{Product: fmt.Sprintf("pkg:npm/p%03d", i), Version: &v, Status: core.Vulnerable, Fix: &fix}, Sources: []string{"bun.lock"}}
	for a := 0; a < advisories; a++ {
		r.Advisories = append(r.Advisories, core.VerdictAdvisory{ID: fmt.Sprintf("ADV-%d-%d", i, a), Severity: "high", URL: "https://osv.dev/vulnerability/x"})
	}
	return r
}

// A project can have 200 vulnerable packages: the worst 25 by default, then a count, each with its worst advisory. A
// Next.js row stays visible whatever comes before it. --all prints every row and every advisory.
func TestTerminalViewCapsPackageRowsButNeverNext(t *testing.T) {
	next := "15.0.0"
	rep := &Report{Tool: Tool_{"rasoat", "0"}, Target: Target{"dir", "."}, Data: DataInfo{Built: "2026-11-16", Origin: "cached"}}
	for i := 0; i < 200; i++ {
		rep.Results = append(rep.Results, pkgResult(i, 6))
	}
	rep.Results = append(rep.Results, Result{Verdict: core.Verdict{Product: "next", Version: &next, Status: core.Vulnerable, Advisories: []core.VerdictAdvisory{}}, Sources: []string{"bun.lock"}})
	rep.Summary = Summary{Vulnerable: 201, OK: 1300}

	out := Render(rep, "en", false)
	if n := strings.Count(out, "VULNERABLE"); n != 25+1 {
		t.Errorf("%d rows shown, want 25 packages and Next.js", n)
	}
	if !strings.Contains(out, "+175 more (--all or --json)") || !strings.Contains(out, "Next.js 15.0.0") {
		t.Errorf("\n%s", out)
	}
	if strings.Contains(out, "ADV-0-1 ") || !strings.Contains(out, "ADV-0-0") || !strings.Contains(out, "+5 more") {
		t.Errorf("a package shows its worst advisory and a count of the rest:\n%s", out)
	}
	all := Render(rep, "en", true)
	if n := strings.Count(all, "VULNERABLE"); n != 201 || strings.Count(all, "ADV-199-") != 6 {
		t.Errorf("--all: %d rows", n)
	}
}

// Clean packages only: no row, and not "nothing identified".
func TestOnlyCleanPackagesIsNotNothingIdentified(t *testing.T) {
	rep := &Report{Tool: Tool_{"rasoat", "0"}, Target: Target{"dir", "."}, Data: DataInfo{Built: "2026-11-16", Origin: "cached"}, Results: []Result{}, Summary: Summary{OK: 12}, Notes: []string{"packages-checked:npm:12:0"}}
	out := Render(rep, "en", false)
	if strings.Contains(out, "Nothing identified") || !strings.Contains(out, "0 vulnerable, 0 unsupported, 0 unknown, 12 ok") || !strings.Contains(out, "npm: 12 packages checked, 0 vulnerable") {
		t.Errorf("\n%s", out)
	}
}
