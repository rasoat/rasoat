package main

// `rasoat scan` on a project's lockfiles, end to end: the program in a subprocess, a real HTTP server serving the real
// reduced ecosystem rows in fixtures/eco (see scripts/cli/eco-testdata.ts).
import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func ecoServer(t *testing.T) (env map[string]string, requested *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.String())
		b, err := os.ReadFile(filepath.Join("fixtures", "eco", filepath.Base(r.URL.Path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL, "CACHE": t.TempDir()}, &asked
}

func TestScanJudgesEveryCargoCrate(t *testing.T) {
	env, asked := ecoServer(t)
	code, v := scanJSON(t, fixture("cargo"), env, "--lang=en")
	rows := results(v)
	if code != 1 || len(rows) != 1 {
		t.Fatalf("exit %d, rows %v", code, rows)
	}
	r := rows[0]
	if r["product"] != "pkg:cargo/tokio" || r["version"] != "1.53.1" || r["status"] != "vulnerable" || r["fix"] != "1.53.3" || r["noFix"] != false {
		t.Errorf("%v", r)
	}
	if s := r["sources"].([]any); len(s) != 1 || s[0] != "Cargo.lock" {
		t.Errorf("sources %v", s)
	}
	// bytes is clean: counted, with no row of its own
	if sum := v["summary"].(map[string]any); sum["vulnerable"] != 1.0 || sum["ok"] != 1.0 {
		t.Errorf("summary %v", sum)
	}
	if notes := v["notes"].([]any); !slices.Contains(notes, any("packages-checked:cargo:2:1")) {
		t.Errorf("notes %v", notes)
	}
	if nc := v["not_checked"].([]any); slices.Contains(nc, any("other-dependencies")) {
		t.Errorf("a judged ecosystem must leave the not-checked list: %v", nc)
	}
	if !slices.Equal(*asked, []string{"/eco-cargo.tsv.gz"}) {
		t.Errorf("requested %v: only the ecosystem file, never a package", *asked)
	}
}

func TestScanGoSumJudgesModulesAndCountsTheCleanOnes(t *testing.T) {
	env, _ := ecoServer(t)
	code, v := scanJSON(t, fixture("go"), env, "--lang=en")
	rows := results(v)
	if code != 1 || len(rows) != 1 {
		t.Fatalf("exit %d, rows %v", code, rows)
	}
	// Go modules carry their v, and the advisories of one flaw in two databases are listed once.
	if r := rows[0]; r["product"] != "pkg:golang/golang.org/x/net" || r["version"] != "v0.54.0" || r["fix"] != "0.62.0" {
		t.Errorf("%v", r)
	}
	if sum := v["summary"].(map[string]any); sum["ok"] != 4.0 {
		t.Errorf("summary %v (five modules in go.sum, one vulnerable; go.mod is not read next to a go.sum)", sum)
	}
}

func TestScanNpmRowsAreAPurlAndNextIsNotDoubled(t *testing.T) {
	env, _ := ecoServer(t)
	_, v := scanJSON(t, fixture("bun"), env, "--lang=en")
	var names []string
	for _, r := range results(v) {
		names = append(names, r["product"].(string))
	}
	if !slices.Contains(names, "next") || !slices.Contains(names, "pkg:npm/postcss") || slices.Contains(names, "pkg:npm/next") {
		t.Errorf("%v", names)
	}
}

// No data is not a clean bill: exit 3, an unknown row that says why, nothing counted ok.
func TestScanOfflineWithoutDataIsExit3(t *testing.T) {
	code, v := scanJSON(t, fixture("cargo"), map[string]string{"RASOAT_LINUX_DATA_URL": nowhere})
	rows := results(v)
	if code != 3 || len(rows) != 1 || rows[0]["status"] != "unknown" || rows[0]["reason"] != "advisory-data-not-available" || rows[0]["product"] != "pkg:cargo/*" {
		t.Fatalf("exit %d, rows %v", code, rows)
	}
	if v["summary"].(map[string]any)["ok"] != 0.0 {
		t.Errorf("%v", v["summary"])
	}
}
