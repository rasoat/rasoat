// Package report turns findings into the one document everything prints: --json as is, the terminal view, the exit code.
package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
	"github.com/rasoat/rasoat/internal/linux"
	"github.com/rasoat/rasoat/internal/project"
	"github.com/rasoat/rasoat/internal/site"
)

//go:embed version.txt
var versionFile string

// Version is this program's version; the release tag must equal it.
var Version = strings.TrimSpace(versionFile)

const Tool = "rasoat"

type Result struct {
	core.Verdict
	Sources []string `json:"sources"`
	How     *string  `json:"how"`
}

type Target struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type DataInfo struct {
	Built   string  `json:"built"`
	Origin  string  `json:"origin"`
	AgeDays int     `json:"age_days"`
	Stale   bool    `json:"stale"`
	Problem *string `json:"problem"`
}

type SiteInfo struct {
	Outcome       string  `json:"outcome"`
	Status        *int    `json:"status"`
	By            *string `json:"by"`
	Cause         *string `json:"cause"`
	TLSUnverified bool    `json:"tls_unverified"`
}

// HostInfo is the part of a report only a machine has.
type HostInfo struct {
	Distro        string  `json:"distro"`
	Name          string  `json:"name"`
	Family        *string `json:"family"`
	Packages      int     `json:"packages"`
	OpenNoFix     int     `json:"open_no_fix"` // published CVEs reaching installed packages with no fix yet: not findings
	KernelRunning *string `json:"kernel_running"`
	KernelNewest  *string `json:"kernel_newest"`
	RebootNeeded  bool    `json:"reboot_needed"`
	InContainer   bool    `json:"in_container"`
	UpgradeCmd    *string `json:"upgrade_command"` // upgrades what was found; run nothing without consent
}

type Summary struct {
	Vulnerable  int `json:"vulnerable"`
	Unsupported int `json:"unsupported"`
	OK          int `json:"ok"`
	Unknown     int `json:"unknown"`
}

type Tool_ struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Report struct {
	Schema     int       `json:"schema"`
	Tool       Tool_     `json:"tool"`
	Target     Target    `json:"target"`
	Data       DataInfo  `json:"data"`
	Site       *SiteInfo `json:"site"`
	Host       *HostInfo `json:"host,omitempty"`
	Results    []Result  `json:"results"`
	Summary    Summary   `json:"summary"`
	Notes      []string  `json:"notes"` // machine words: binary-bun-lock, truncated, or <runtime>-min:<version>
	NotChecked []string  `json:"not_checked"`
	Notices    []string  `json:"notices"`
	ExitCode   int       `json:"exit_code"`
}

// NotChecked is said on every run: a clean result covers only these products, and "no findings" reads as "safe" otherwise.
var NotChecked = []string{"wordpress-plugins-themes", "other-dependencies", "other-frameworks"}

// NotCheckedHost is the same promise for a machine: a package manager's view, and fixes that exist.
var NotCheckedHost = []string{"software-outside-the-package-manager", "advisories-with-no-published-fix", "whether-a-flaw-is-reachable-on-this-machine", "kernel-configuration", "project-dependencies"}

// Today is the date verdicts are judged at.
func Today() string { return time.Now().UTC().Format("2006-01-02") }

func rank(status string) int {
	switch status {
	case core.Vulnerable:
		return 0
	case core.Unsupported:
		return 1
	case core.Unknown:
		return 2
	}
	return 3
}

// Exit: 1 = act on it. 3 = no proof either way: nothing identified, or a version we cannot judge. 0 only when all is
// judged clean.
func exitCode(s Summary, total int) int {
	switch {
	case s.Vulnerable+s.Unsupported > 0:
		return 1
	case s.Unknown > 0 || total == 0:
		return 3
	}
	return 0
}

func tally(results []Result) Summary {
	var s Summary
	for _, r := range results {
		switch r.Status {
		case core.Vulnerable:
			s.Vulnerable++
		case core.Unsupported:
			s.Unsupported++
		case core.OK:
			s.OK++
		default:
			s.Unknown++
		}
	}
	return s
}

// DataOf is the data block of a report.
func DataOf(l *data.Loaded) DataInfo {
	return DataInfo{l.Snapshot.Built, l.Origin, l.AgeDays, l.Stale, l.Problem}
}

func assemble(target Target, l *data.Loaded, results []Result, si *SiteInfo, notes []string) *Report {
	sort.SliceStable(results, func(i, j int) bool { return rank(results[i].Status) < rank(results[j].Status) })
	if notes == nil {
		notes = []string{}
	}
	if results == nil {
		results = []Result{}
	}
	s := tally(results)
	return &Report{
		Schema: 1, Tool: Tool_{Tool, Version}, Target: target, Data: DataOf(l), Site: si, Results: results, Summary: s,
		Notes: notes, NotChecked: NotChecked, Notices: core.NOTICES, ExitCode: exitCode(s, len(results)),
	}
}

// Dir is the report for a scanned directory.
func Dir(root string, w project.Walked, l *data.Loaded) *Report {
	var results []Result
	index := map[string]int{}
	today := Today()
	for _, f := range w.Found {
		key := f.Product + " " + f.Version
		i, ok := index[key]
		if !ok {
			v := f.Version
			i = len(results)
			index[key] = i
			results = append(results, Result{Verdict: core.VerdictFor(f.Product, &v, l.Snapshot, today), Sources: []string{}})
		}
		seen := false
		for _, s := range results[i].Sources {
			seen = seen || s == f.Path
		}
		if !seen {
			results[i].Sources = append(results[i].Sources, f.Path)
		}
	}
	return assemble(Target{"dir", root}, l, results, nil, w.Notes)
}

// Host is the report for a machine or a mounted root.
func Host(h *linux.Host, root string) *Report {
	results := make([]Result, 0, len(h.Findings))
	for _, f := range h.Findings {
		sources := f.Installed
		if sources == nil {
			sources = []string{}
		}
		results = append(results, Result{Verdict: f.Verdict, Sources: sources, How: opt(f.How)})
	}
	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := rank(results[i].Status), rank(results[j].Status)
		if ri != rj {
			return ri < rj
		}
		return worst(results[i]) < worst(results[j])
	})
	// A package with nothing found counts as ok without a row of its own: a machine has hundreds.
	s := tally(results)
	s.OK += h.OK
	built, origin, problem := h.Data.Built, h.Data.Origin, h.Data.Problem
	if built == "" {
		built, origin = h.Index.Built, h.Index.Origin
	}
	if problem == "" {
		problem = h.Index.Problem
	}
	if origin == "" {
		origin = "none"
	}
	info := DataInfo{Built: built, Origin: origin, Problem: opt(problem)}
	if t, err := time.Parse("2006-01-02", built); err == nil {
		info.AgeDays = max(0, int(time.Since(t).Hours()/24))
		info.Stale = info.AgeDays > 7
	}
	return &Report{
		Schema: 1, Tool: Tool_{Tool, Version}, Target: Target{"host", root}, Data: info,
		Host: &HostInfo{Distro: h.Distro.ID, Name: h.Distro.Name, Family: opt(h.Family), Packages: h.Packages, OpenNoFix: h.Open,
			KernelRunning: opt(h.Running), KernelNewest: opt(h.Newest), RebootNeeded: h.Reboot, InContainer: h.InContainer, UpgradeCmd: opt(h.UpgradeCmd)},
		Results: results, Summary: s, Notes: h.Notes, NotChecked: NotCheckedHost, Notices: append(append([]string{}, core.NOTICES...), linux.Notices...), ExitCode: exitCode(s, len(results)),
	}
}

func worst(r Result) int {
	best := 5
	for _, a := range r.Advisories {
		best = min(best, core.SeverityRank(a.Severity))
	}
	return best
}

func short(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Site is the report for a site read from outside.
func Site(target string, o site.Outcome, l *data.Loaded) *Report {
	if o.Kind != "result" {
		return assemble(Target{"url", target}, l, nil, &SiteInfo{Outcome: o.Kind, Status: o.Status, By: opt(o.By), Cause: opt(o.Cause)}, nil)
	}
	today := Today()
	var results []Result
	var notes []string
	for _, f := range o.Findings {
		where := f.Where
		if where == "" {
			where = o.URL
		}
		results = append(results, Result{Verdict: core.VerdictFor(f.Framework, opt(f.Version), l.Snapshot, today), Sources: []string{short(where, 200)}, How: opt(f.How)})
	}
	for _, r := range o.Runtimes {
		if r.Version != "" {
			v := r.Version
			results = append(results, Result{Verdict: core.VerdictFor(r.Runtime, &v, l.Snapshot, today), Sources: []string{short(o.URL, 200)}, How: opt(r.How)})
		} else if r.Min != "" {
			notes = append(notes, r.Runtime+"-min:"+r.Min) // not visible from outside: a bound, not a verdict
		}
	}
	return assemble(Target{"url", short(o.URL, 300)}, l, results, &SiteInfo{Outcome: "ok", TLSUnverified: o.TLSUnverified}, notes)
}

var c1 = core.NewRe(`[\x{007f}-\x{009f}]`)

// JSON marshals with C1 controls escaped: a terminal can act on them, and text here comes from advisories and from sites.
func JSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return c1.ReplaceAllStringFunc(strings.TrimSuffix(b.String(), "\n"), func(s string) string {
		return fmt.Sprintf(`\u%04x`, []rune(s)[0])
	})
}
