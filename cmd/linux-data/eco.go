package main

// The language-ecosystem files `rasoat scan` downloads: one per OSV ecosystem (npm, crates.io, Go), every package that has
// a published advisory and the version ranges it reaches. No advisory prose. Same header and terms rules as a distro file.

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ecoSources: an OSV export, and the data file its ranges go to. The file id is what the CLI asks for, never a package.
var ecoSources = []struct{ export, id string }{
	{"npm", "eco-npm"},
	{"crates.io", "eco-cargo"},
	{"Go", "eco-go"},
}

// span is one affected range of one package: introduced <= v < fixed, or <= last. Both empty: no fix is published.
type span struct {
	id, introduced, fixed, last, severity string
	aliases                               []string
}

type ecoFile struct {
	pkgs     map[string][]span
	prefixes map[string]bool // advisory-id prefixes present: the terms the header must state
	skipped  map[string]int  // records left out because no terms.json row covers their source, by id prefix
}

func newEcoFile() *ecoFile {
	return &ecoFile{pkgs: map[string][]span{}, prefixes: map[string]bool{}, skipped: map[string]int{}}
}

// adviceTerms is the terms of the source behind an advisory id; false when terms.json does not know it.
func adviceTerms(id string) (Terms, bool) {
	for _, t := range terms.Advisories {
		if strings.HasPrefix(id, t.Prefix) {
			return t, true
		}
	}
	return Terms{}, false
}

var ghsaSeverity = map[string]string{"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}

// ecoSeverity: a malicious package is the worst case there is; a GitHub advisory states its own word; otherwise the
// CVSS score through severityOf. The summary is dropped first: severityOf reads a leading "Critical" there as Red Hat's.
func ecoSeverity(r *record) string {
	if strings.HasPrefix(r.ID, "MAL-") {
		return "critical"
	}
	if s := ghsaSeverity[strings.ToUpper(r.DatabaseSpecific.Severity)]; s != "" {
		return s
	}
	c := *r
	c.Summary = ""
	if s := severityOf(&c, ""); s != "unknown" {
		return s
	}
	for _, a := range r.Affected { // RustSec keeps its vector on the package
		var vector string
		if json.Unmarshal(a.DatabaseSpecific.CVSS, &vector) == nil && strings.HasPrefix(vector, "CVSS:3") {
			c.Severity = nil
			c.Severity = append(c.Severity, struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			}{"CVSS_V3", vector})
			return severityOf(&c, "")
		}
	}
	return "unknown"
}

// notVulnerability: RustSec files "unmaintained" and "notice" next to its vulnerabilities. They are warnings in cargo audit
// too, not a hole in this version: reporting a crate as VULNERABLE for being abandoned would teach people to ignore the word.
// "unsound" stays: it is a soundness bug in safe code.
func notVulnerability(a *affected) bool {
	var kind string
	return json.Unmarshal(a.DatabaseSpecific.Informational, &kind) == nil && (kind == "unmaintained" || kind == "notice")
}

var aliasPrefixes = []string{"CVE-", "GHSA-", "GO-", "RUSTSEC-"}

func aliasesOf(r *record) []string {
	var out []string
	for _, a := range r.Aliases {
		for _, p := range aliasPrefixes {
			if strings.HasPrefix(a, p) && a != r.ID {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// spansOf turns one affected entry into ranges. Events run in order: introduced opens a range, fixed or last_affected
// closes it. An entry with no range but an exact version list becomes one single-version range per version.
func spansOf(id, sev string, aliases []string, a *affected) []span {
	var out []span
	add := func(intro, fixed, last string) {
		out = append(out, span{id, intro, fixed, last, sev, aliases})
	}
	ranged := false
	for _, g := range a.Ranges {
		if g.Type != "SEMVER" && g.Type != "ECOSYSTEM" {
			continue // GIT ranges are commits, not versions
		}
		ranged = true
		open, intro := false, ""
		for _, ev := range g.Events {
			switch {
			case ev.Introduced != "":
				if open {
					add(intro, "", "")
				}
				open, intro = true, ev.Introduced
			case ev.Fixed != "":
				if !open {
					intro = "0"
				}
				add(intro, ev.Fixed, "")
				open = false
			case ev.LastAffected != "":
				if !open {
					intro = "0"
				}
				add(intro, "", ev.LastAffected)
				open = false
			}
		}
		if open {
			add(intro, "", "")
		}
	}
	if !ranged {
		for _, v := range a.Versions {
			add(v, "", v)
		}
	}
	return out
}

func collectEco(z *zip.Reader, export string, out *ecoFile) error {
	for _, f := range z.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		var r record
		err = json.NewDecoder(rc).Decode(&r)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if r.Withdrawn != "" {
			continue
		}
		t, ok := adviceTerms(r.ID)
		if !ok {
			out.skipped[strings.SplitN(r.ID, "-", 2)[0]]++
			continue
		}
		sev, aliases := ecoSeverity(&r), aliasesOf(&r)
		for i := range r.Affected {
			a := &r.Affected[i]
			if a.Package.Ecosystem != export || a.Package.Name == "" || notVulnerability(a) {
				continue
			}
			for _, s := range spansOf(r.ID, sev, aliases, a) {
				out.pkgs[a.Package.Name] = append(out.pkgs[a.Package.Name], s)
				out.prefixes[t.Prefix] = true
			}
		}
	}
	return nil
}

// ecoHeader joins the terms of every source in the file: the flat fields a reader of any data file expects, and the full
// rows under "sources".
func ecoHeader(id, built string, records int, prefixes map[string]bool) map[string]any {
	var used []Terms
	for _, t := range terms.Advisories {
		if prefixes[t.Prefix] {
			used = append(used, t)
		}
	}
	join := func(f func(Terms) string) string {
		var parts []string
		for _, t := range used {
			parts = append(parts, f(t))
		}
		return strings.Join(parts, "; ")
	}
	return map[string]any{"format": 1, "id": id, "built": built, "records": records,
		"source": join(func(t Terms) string { return t.Source }), "sourceUrl": join(func(t Terms) string { return t.SourceURL }),
		"license": join(func(t Terms) string { return t.License }), "licenseUrl": join(func(t Terms) string { return t.LicenseURL }),
		"changes": terms.Changes, "sources": used}
}

// A file: one JSON header line, then package, id, introduced, fixed, last_affected, severity, aliases (TAB-separated).
func writeEco(path, id, built string, e *ecoFile) (int, error) {
	names := make([]string, 0, len(e.pkgs))
	count := 0
	for n, spans := range e.pkgs {
		seen := map[string]bool{}
		kept := spans[:0]
		for _, s := range spans {
			if k := s.id + "\t" + s.introduced + "\t" + s.fixed + "\t" + s.last; !seen[k] {
				seen[k] = true
				kept = append(kept, s)
			}
		}
		sort.SliceStable(kept, func(i, j int) bool { return kept[i].id < kept[j].id })
		e.pkgs[n] = kept
		count += len(kept)
		names = append(names, n)
	}
	sort.Strings(names)
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	z, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	w := bufio.NewWriter(z)
	head, _ := json.Marshal(ecoHeader(id, built, count, e.prefixes))
	w.Write(head)
	w.WriteByte('\n')
	for _, n := range names {
		for _, s := range e.pkgs[n] {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", clean(n), clean(s.id), clean(s.introduced), clean(s.fixed), clean(s.last), s.severity, clean(strings.Join(s.aliases, ",")))
		}
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	return count, z.Close()
}
