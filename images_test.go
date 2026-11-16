package main

// Images and CI pins end to end: files written as our own repos write them, the release lines from a real HTTP server.
import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const linesIndex = `{"format":1,"built":"2026-11-16","files":{},"lines":{
 "postgresql":[{"cycle":"17","eol":"2099-01-01","latest":"17.12"},{"cycle":"16","eol":"2099-01-01","latest":"16.16"},{"cycle":"13","eol":"2020-01-01","latest":"13.23"}],
 "redis":[{"cycle":"7.4","eol":"","latest":"7.4.9"}],
 "debian":[{"cycle":"12","eol":"2099-01-01","latest":"12.15"}]}}`

func imageProject(t *testing.T) string {
	d := t.TempDir()
	write(t, d, "Dockerfile", "ARG BUN_VERSION=1.4.4\nFROM oven/bun:${BUN_VERSION} AS base\nFROM base AS run\nFROM debian:bookworm-slim\n")
	write(t, d, "docker-compose.yml", "services:\n  db:\n    image: postgres:16-alpine\n  old:\n    image: postgres:13.1\n  cache:\n    image: redis:7.4.1\n  mail:\n    image: axllent/mailpit:latest\n")
	write(t, d, ".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - uses: oven-sh/setup-bun@v2\n        with: { bun-version: 1.4.4 }\n")
	return d
}

func TestImagesAndCIPins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(linesIndex))
	}))
	defer srv.Close()
	d := imageProject(t)
	code, r := scanJSON(t, d, map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL}, "--lang=en")
	if code != 1 {
		t.Errorf("exit %d", code) // postgres 13 ended
	}
	byKey := map[string]rep{}
	for _, x := range results(r) {
		byKey[x["product"].(string)+" "+x["version"].(string)] = x
	}
	sources := func(k string) []string {
		var out []string
		for _, s := range byKey[k]["sources"].([]any) {
			out = append(out, s.(string))
		}
		return out
	}
	// A Dockerfile ARG and a CI pin name the same Bun: one row, both files, judged by the verdict a .bun-version gets.
	if got := sources("bun 1.4.4"); !slices.Equal(got, []string{".github/workflows/ci.yml (bun-version: 1.4.4)", "Dockerfile (oven/bun:1.4.4)"}) {
		t.Errorf("bun sources: %v", got)
	}
	if x := byKey["postgresql 13.1"]; x["status"] != "unsupported" || x["fix"] != "16.16" {
		t.Errorf("ended line: %v", x)
	}
	if x := byKey["postgresql 16"]; x["status"] != "unknown" || x["reason"] != "version-not-exact" {
		t.Errorf("line tag: %v", x)
	}
	if x := byKey["redis 7.4.1"]; x["status"] != "unknown" || x["reason"] != "no-advisory-data" || x["fix"] != "7.4.9" {
		t.Errorf("exact tag, no advisory data: %v", x)
	}
	if x := byKey["debian 12"]; x["status"] != "unknown" || x["reason"] != "distro-release-supported" {
		t.Errorf("distro: %v", x)
	}
	if notes := r["notes"].([]any); !slices.Contains(notes, any("image-not-judged:docker-compose.yml (axllent/mailpit:latest)")) {
		t.Errorf("an image with no family is listed: %v", notes)
	}
	// The release lines are one GET naming no project: a directory with no image never makes it.
	hits := 0
	counted := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer counted.Close()
	scanJSON(t, t.TempDir(), map[string]string{"RASOAT_LINUX_DATA_URL": counted.URL}, "--lang=en")
	if hits != 0 {
		t.Errorf("%d requests for a directory with no image", hits)
	}
}

func TestImagesOffline(t *testing.T) {
	d := imageProject(t)
	_, r := scanJSON(t, d, nil) // --offline, no cache: no lines
	for _, x := range results(r) {
		if x["product"] == "postgresql" && x["reason"] != "line-data-not-available" {
			t.Errorf("%v", x)
		}
	}
	out := rasoat(t, t.TempDir(), nil, "", "scan", d, "--offline")
	if !strings.Contains(out.stdout, "Image not judged, no data for it: docker-compose.yml (axllent/mailpit:latest)") {
		t.Error(out.stdout)
	}
}
