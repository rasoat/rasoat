package main

// `rasoat discover` and the not_judged list of a scan report: the walk without the judging, end to end.
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// inventoryDir is a project with something of every kind, and two references no data judges: an image outside the family
// table, and an image whose tag is a variable.
func inventoryDir(t *testing.T) string {
	d := t.TempDir()
	write(t, d, "package-lock.json", lock("14.2.3"))
	write(t, d, "Cargo.lock", "version = 4\n\n[[package]]\nname = \"bytes\"\nversion = \"1.12.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.53.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	write(t, d, "Dockerfile", "FROM oven/bun:1.4.4\n")
	write(t, d, ".nvmrc", "22.3.0\n")
	write(t, d, "docker-compose.yml", "services:\n  db:\n    image: postgres:16-alpine\n  mail:\n    image: axllent/mailpit:3.1.0\n  app:\n    image: ${REGISTRY}/app:${TAG}\n")
	write(t, d, ".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - uses: actions/setup-go@v5\n        with: { go-version: 1.22.5 }\n")
	return d
}

// noNetwork is an environment in which any request is counted: discover must make none.
func noNetwork(t *testing.T) (env map[string]string, hits *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n++; http.NotFound(w, r) }))
	t.Cleanup(srv.Close)
	return map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL, "RASOAT_DATA_URL": srv.URL + "/snapshot"}, &n
}

func items(v rep) []rep {
	out := []rep{}
	for _, i := range v["items"].([]any) {
		out = append(out, i.(rep))
	}
	return out
}

func TestDiscoverListsEveryComponentAndWhatJudgesIt(t *testing.T) {
	env, hits := noNetwork(t)
	cache := t.TempDir()
	r := rasoat(t, cache, env, "", "discover", inventoryDir(t), "--json")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var v rep
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil {
		t.Fatal(err, r.stdout)
	}
	if v["schema"] != 1.0 || v["kind"] != "inventory" || v["target"].(rep)["kind"] != "dir" {
		t.Errorf("shape: %v", v)
	}
	by := map[string]string{}    // "kind product version" -> judged_by
	where := map[string]string{} // same key -> file
	for _, i := range items(v) {
		ver, _ := i["version"].(string)
		key := i["kind"].(string) + " " + i["product"].(string) + " " + ver
		judged, _ := i["judged_by"].(string)
		by[key], where[key] = judged, i["where"].(string)
	}
	want := map[string]string{
		"pin next 14.2.3":                "snapshot",
		"pin node 22.3.0":                "snapshot",
		"pin bun 1.4.4":                  "snapshot",
		"image postgresql 16":            "lines",
		"pin go 1.22.5":                  "lines",
		"image axllent/mailpit 3.1.0":    "", // no family: the tag as written
		"package pkg:cargo/tokio 1.53.1": "eco-cargo",
		"package pkg:cargo/bytes 1.12.1": "eco-cargo",
	}
	for k, judged := range want {
		if got, ok := by[k]; !ok || got != judged {
			t.Errorf("%q: judged_by %q (present %v), want %q", k, got, ok, judged)
		}
	}
	// next is a pin with its own verdict: its npm package row would double it
	for k := range by {
		if strings.HasPrefix(k, "package pkg:npm/next ") {
			t.Errorf("next listed as a package: %s", k)
		}
	}
	var unresolved rep
	for _, i := range items(v) {
		if i["unresolved"] == true {
			unresolved = i
		}
	}
	if unresolved == nil || unresolved["judged_by"] != nil || unresolved["where"] != "docker-compose.yml" || unresolved["ref"] != "${REGISTRY}/app:${TAG}" {
		t.Errorf("an unresolved reference is listed, judged by nothing: %v", unresolved)
	}
	sum := v["summary"].(rep)
	if sum["not_judged"] != 2.0 || sum["packages"].(rep)["cargo"] != 2.0 {
		t.Errorf("summary %v", sum)
	}
	if *hits != 0 {
		t.Errorf("discover made %d requests", *hits)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("discover wrote to the cache: %v", entries)
	}
}

func TestDiscoverInTheTerminalCountsPackagesAndNamesWhatIsNotJudged(t *testing.T) {
	env, hits := noNetwork(t)
	r := rasoat(t, t.TempDir(), env, "", "discover", inventoryDir(t))
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, s := range []string{"pin    Bun 1.4.4  Dockerfile (oven/bun:1.4.4)  [snapshot]", "[no data judges this]", "cargo: 2 packages in lockfiles", "components, ", "2 not judged"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("missing %q in\n%s", s, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "tokio") {
		t.Error("packages are counted in the terminal, not listed")
	}
	if *hits != 0 {
		t.Errorf("%d requests", *hits)
	}
	if r := rasoat(t, t.TempDir(), env, "", "discover", "/no/such/dir"); r.code != 2 {
		t.Errorf("a missing directory is a usage error: %d", r.code)
	}
	if r := rasoat(t, t.TempDir(), env, "", "discover", "example.com"); r.code != 2 {
		t.Errorf("discover reads a directory, never an address: %d", r.code)
	}
}

func TestAScanReportListsWhatNoDataJudgedAsNotJudged(t *testing.T) {
	env, _ := ecoServer(t)
	dir := inventoryDir(t)
	_, scanned := scanJSON(t, dir, env, "--lang=en")
	list := scanned["not_judged"].([]any)
	if len(list) != 2 {
		t.Fatalf("not_judged %v", list)
	}
	// the same shape as discover's items, and the notes stay for the clients that read them
	var products []string
	for _, i := range list {
		x := i.(rep)
		if x["judged_by"] != nil || x["where"] != "docker-compose.yml" {
			t.Errorf("%v", x)
		}
		products = append(products, x["product"].(string))
	}
	if !slices.Contains(products, "axllent/mailpit") {
		t.Errorf("%v", products)
	}
	notes := scanned["notes"].([]any)
	if !slices.Contains(notes, any("image-not-judged:docker-compose.yml (axllent/mailpit:3.1.0)")) {
		t.Errorf("notes %v", notes)
	}
	_, empty := scanJSON(t, t.TempDir(), env)
	if l, ok := empty["not_judged"].([]any); !ok || len(l) != 0 {
		t.Errorf("an empty list, not null: %v", empty["not_judged"])
	}
}

func TestNothingIdentifiedNamesWhatIsReadNow(t *testing.T) {
	for lang, words := range map[string][]string{"en": {"crates.io", "lockfile", "image", "CI pin"}, "vi": {"crates.io", "lockfile", "image", "ghim CI"}} {
		r := rasoat(t, t.TempDir(), nil, "", "scan", t.TempDir(), "--offline", "--lang", lang)
		for _, w := range words {
			if !strings.Contains(r.stdout, w) {
				t.Errorf("%s: %q missing from %s", lang, w, r.stdout)
			}
		}
	}
}

func TestHelpListsDiscoverAndDb(t *testing.T) {
	r := rasoat(t, t.TempDir(), nil, "", "--help")
	for _, s := range []string{"rasoat discover [dir]", "rasoat db status", "rasoat db update"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("--help lacks %q", s)
		}
	}
	if r := rasoat(t, t.TempDir(), nil, "", "db"); r.code != 2 {
		t.Errorf("db alone is a usage error: %d", r.code)
	}
	if r := rasoat(t, t.TempDir(), nil, "", "db", "wipe"); r.code != 2 {
		t.Errorf("an unknown db command is a usage error: %d", r.code)
	}
}
