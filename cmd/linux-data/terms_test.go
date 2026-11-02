package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every family the builder writes has a full row: a source, a licence and a link. An unstated licence is allowed, but it
// must then have no licence link, so a reader sees a gap and not a claim.
func TestEveryFamilyHasTerms(t *testing.T) {
	for _, id := range []string{"ubuntu-24.04", "alpine-3.20", "rhel-9", "almalinux-9", "rocky-9", "debian-12", "sles-15.6", "opensuse-15.6", "linux-kernel"} {
		x := sourceOf(id)
		if x.Source == "" || x.License == "" || !strings.HasPrefix(x.SourceURL, "https://") {
			t.Errorf("%s: incomplete terms: %+v", id, x)
		}
		if x.LicenseURL != "" && !strings.HasPrefix(x.LicenseURL, "https://") {
			t.Errorf("%s: licence link is not https: %q", id, x.LicenseURL)
		}
		if x.License == "not stated at the source" && x.LicenseURL != "" {
			t.Errorf("%s: claims a licence link that does not exist: %q", id, x.LicenseURL)
		}
	}
}

// The default row must be the only one without a prefix, and it must be last: sourceOf walks the list in order.
func TestDefaultRowIsLast(t *testing.T) {
	for i, x := range terms.Sources {
		if x.Prefix == "" && i != len(terms.Sources)-1 {
			t.Fatalf("prefixless row at %d, not last", i)
		}
	}
	if sourceOf("linux-kernel").Prefix != "" {
		t.Error("the kernel must fall through to the default row")
	}
	if got := sourceOf("almalinux-9").License; got != "MIT" {
		t.Errorf("almalinux licence = %q, want MIT", got)
	}
	if got := sourceOf("opensuse-15.6").Source; got != "SUSE security data, through OSV.dev" {
		t.Errorf("opensuse source = %q", got)
	}
}

func TestFileHeaderAndNoticeCarryTerms(t *testing.T) {
	dir := t.TempDir()
	rel := &release{pkgs: map[string][]entry{"bash": {{id: "UBUNTU-1", fixed: "5.0-1", severity: "high"}}}, open: map[string]map[string]bool{}}
	if _, err := writeRelease(filepath.Join(dir, "ubuntu-24.04.tsv.gz"), "ubuntu-24.04", "2026-11-02", rel); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "ubuntu-24.04.tsv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	head, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.SplitN(string(head), "\n", 2)[0]
	var h map[string]any
	if err := json.Unmarshal([]byte(line), &h); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"source", "sourceUrl", "license", "licenseUrl", "changes"} {
		if v, _ := h[k].(string); v == "" {
			t.Errorf("header has no %s: %s", k, line)
		}
	}
	if h["license"] != "CC-BY-SA-4.0" {
		t.Errorf("ubuntu licence = %v", h["license"])
	}

	if err := writeNotice(dir); err != nil {
		t.Fatal(err)
	}
	notice, err := os.ReadFile(filepath.Join(dir, "NOTICE.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CC-BY-SA-4.0", "Debian", "SUSE", "not stated at the source", "CVE-ToU", "Apache-2.0"} {
		if !strings.Contains(string(notice), want) {
			t.Errorf("NOTICE.txt does not mention %q", want)
		}
	}
}
