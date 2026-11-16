package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Records as OSV serves them (trimmed of prose): a GHSA with its own severity word, a RustSec advisory that lists its
// vector on the package, a malicious-package record, a Go record with two ranges, and the ones that must not get through.
var ecoRecords = map[string]string{
	"GHSA-x.json": `{"id":"GHSA-x","aliases":["CVE-2020-1","GHSA-x"],"summary":"Critical: not a Red Hat word","database_specific":{"severity":"MODERATE"},
	  "affected":[{"package":{"name":"left-pad","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.1"},{"introduced":"2.0.0"},{"last_affected":"2.1.0"}]}]}]}`,
	"MAL-1.json": `{"id":"MAL-2021-1","affected":[{"package":{"name":"evil-pkg","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	"RUSTSEC-1.json": `{"id":"RUSTSEC-2016-0001","aliases":["CVE-2016-10931","GHSA-34p9-f4q3-c4r7"],
	  "affected":[{"package":{"name":"openssl","ecosystem":"crates.io"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-0"},{"fixed":"0.9.0"}]}],"database_specific":{"cvss":"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H","informational":null}}]}`,
	"RUSTSEC-2.json": `{"id":"RUSTSEC-2025-0069","affected":[{"package":{"name":"daemonize","ecosystem":"crates.io"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-0"}]}],"database_specific":{"informational":"unmaintained"}}]}`,
	"RUSTSEC-3.json": `{"id":"RUSTSEC-2025-0001","affected":[{"package":{"name":"soundless","ecosystem":"crates.io"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-0"},{"fixed":"1.0.0"}]}],"database_specific":{"informational":"unsound"}}]}`,
	"GO-1.json":      `{"id":"GO-2020-0001","aliases":["CVE-2020-36567"],"affected":[{"package":{"name":"example.com/gin","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.6.0"}]}]}]}`,
	"WITHDRAWN.json": `{"id":"GHSA-gone","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"name":"left-pad","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	"GSD-1.json":     `{"id":"GSD-2021-1","affected":[{"package":{"name":"left-pad","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	"GIT.json":       `{"id":"GHSA-git","affected":[{"package":{"name":"left-pad","ecosystem":"npm"},"ranges":[{"type":"GIT","events":[{"introduced":"abc"},{"fixed":"def"}]}]}]}`,
	"LIST.json":      `{"id":"GHSA-list","affected":[{"package":{"name":"listed","ecosystem":"npm"},"versions":["1.0.0","1.0.1"]}]}`,
	"OTHER.json":     `{"id":"GHSA-other","affected":[{"package":{"name":"left-pad","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
}

func ecoZip(t *testing.T) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range ecoRecords {
		f, _ := w.Create(name)
		f.Write([]byte(body))
	}
	w.Close()
	z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func readGz(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(z)
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func build(t *testing.T, export, id string) []string {
	t.Helper()
	e := newEcoFile()
	if err := collectEco(ecoZip(t), export, e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), id+".tsv.gz")
	if _, err := writeEco(path, id, "2026-11-16", e); err != nil {
		t.Fatal(err)
	}
	return readGz(t, path)
}

func TestEcoNpmRowsRangesAndSeverity(t *testing.T) {
	lines := build(t, "npm", "eco-npm")
	rows := map[string]bool{}
	for _, l := range lines[1:] {
		rows[l] = true
	}
	for _, want := range []string{
		// the GHSA's own word wins, and a summary that starts with "Critical" is not read as Red Hat's
		"left-pad\tGHSA-x\t0\t1.3.1\t\tmedium\tCVE-2020-1",
		"left-pad\tGHSA-x\t2.0.0\t\t2.1.0\tmedium\tCVE-2020-1",
		"evil-pkg\tMAL-2021-1\t0\t\t\tcritical\t",
		"listed\tGHSA-list\t1.0.0\t\t1.0.0\tunknown\t",
		"listed\tGHSA-list\t1.0.1\t\t1.0.1\tunknown\t",
	} {
		if !rows[want] {
			t.Errorf("missing row %q in\n%s", want, strings.Join(lines, "\n"))
		}
	}
	if len(lines) != 1+5 {
		t.Errorf("withdrawn, git-range, other-ecosystem and unknown-terms (GSD) records must not get through:\n%s", strings.Join(lines, "\n"))
	}
	var h map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatal(err)
	}
	if h["id"] != "eco-npm" || h["format"] != 1.0 || h["records"] != 5.0 || h["license"] != "CC-BY-4.0; Apache-2.0" {
		t.Errorf("header %v", h)
	}
	for _, k := range []string{"source", "sourceUrl", "license", "licenseUrl", "changes"} {
		if v, _ := h[k].(string); v == "" {
			t.Errorf("header has no %s", k)
		}
	}
	if src, _ := h["sources"].([]any); len(src) != 2 {
		t.Errorf("a header states the terms of each source in the file: %v", h["sources"])
	}
}

func TestEcoCargoSkipsAbandonedCratesAndReadsTheVectorOnThePackage(t *testing.T) {
	lines := build(t, "crates.io", "eco-cargo")
	joined := strings.Join(lines[1:], "\n")
	if !strings.Contains(joined, "openssl\tRUSTSEC-2016-0001\t0.0.0-0\t0.9.0\t\thigh\tCVE-2016-10931,GHSA-34p9-f4q3-c4r7") {
		t.Errorf("\n%s", joined)
	}
	if strings.Contains(joined, "daemonize") {
		t.Errorf("an unmaintained crate is a warning, not a vulnerability:\n%s", joined)
	}
	if !strings.Contains(joined, "soundless\tRUSTSEC-2025-0001") {
		t.Errorf("an unsound crate stays:\n%s", joined)
	}
	var h map[string]any
	json.Unmarshal([]byte(lines[0]), &h)
	if h["license"] != "CC0-1.0" {
		t.Errorf("licence %v", h["license"])
	}
}

func TestEcoGoHeaderCarriesItsOwnTerms(t *testing.T) {
	lines := build(t, "Go", "eco-go")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "example.com/gin\tGO-2020-0001\t0\t1.6.0") {
		t.Fatalf("%v", lines)
	}
	var h map[string]any
	json.Unmarshal([]byte(lines[0]), &h)
	if h["license"] != "CC-BY-4.0" || h["id"] != "eco-go" {
		t.Errorf("%v", h)
	}
}

// Every advisory source the three exports carry has a full terms row; an unstated licence has no licence link.
func TestEveryAdvisorySourceHasTerms(t *testing.T) {
	for _, id := range []string{"GHSA-abcd-1234-wxyz", "MAL-2021-1", "RUSTSEC-2016-0001", "GO-2020-0001"} {
		x, ok := adviceTerms(id)
		if !ok || x.Source == "" || x.License == "" || !strings.HasPrefix(x.SourceURL, "https://") || !strings.HasPrefix(x.LicenseURL, "https://") {
			t.Errorf("%s: %+v", id, x)
		}
	}
	if _, ok := adviceTerms("GSD-2021-1"); ok {
		t.Error("an id with no terms row must not be shipped")
	}
	dir := t.TempDir()
	if err := writeNotice(dir); err != nil {
		t.Fatal(err)
	}
	notice, _ := os.ReadFile(filepath.Join(dir, "NOTICE.txt"))
	for _, want := range []string{"GitHub Advisory Database", "OpenSSF Malicious Packages", "RustSec", "Go Vulnerability Database", "CC0-1.0"} {
		if !strings.Contains(string(notice), want) {
			t.Errorf("NOTICE.txt does not mention %q", want)
		}
	}
}
