package osvdb

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rasoat/rasoat/internal/deps"
)

// fixtures/eco holds the real eco-*.tsv.gz rows of the few packages the fixtures use: scripts/cli/eco-testdata.ts cuts them
// from the files the builder wrote, so these tests judge real advisory rows, not invented ones.
func ecoFixtures() string { return filepath.Join("..", "..", "fixtures", "eco") }

func serve(t *testing.T, requested *[]string) string {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*requested = append(*requested, r.URL.String())
		mu.Unlock()
		b, err := os.ReadFile(filepath.Join(ecoFixtures(), filepath.Base(r.URL.Path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("RASOAT_LINUX_DATA_URL", srv.URL)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return srv.URL
}

func TestJudgeFollowsEveryFixToTheLowestCleanVersion(t *testing.T) {
	var asked []string
	serve(t, &asked)
	out := Scan([]deps.Pkg{
		{Eco: deps.NPM, Name: "lodash", Version: "4.17.15", File: "a/bun.lock"},
		{Eco: deps.NPM, Name: "lodash", Version: "4.18.1", File: "a/bun.lock"},
		{Eco: deps.NPM, Name: "postcss", Version: "8.4.31", File: "a/bun.lock"},
		{Eco: deps.NPM, Name: "postcss", Version: "8.4.31", File: "b/pnpm-lock.yaml"},
		{Eco: deps.NPM, Name: "cxp-jquery", Version: "1.0.0", File: "a/bun.lock"},
		{Eco: deps.NPM, Name: "next", Version: "14.2.3", File: "a/bun.lock"}, // Next.js has its own verdict
		{Eco: deps.NPM, Name: "left-pad", Version: "1.3.0", File: "a/bun.lock"},
	}, false, "test")
	if out.NoData["npm"] != nil {
		t.Fatalf("no data: %v, requested %v", out.NoData, asked)
	}
	if out.Checked["npm"] != 5 {
		t.Errorf("checked %d, want 5 (next is left to its own verdict, a package in two files counts once)", out.Checked["npm"])
	}
	got := map[string]Vuln{}
	for _, v := range out.Vulns {
		got[v.Name+"@"+v.Version] = v
	}
	if len(got) != 3 {
		t.Fatalf("vulnerable: %v", got)
	}
	// lodash 4.17.15: 4.17.19, 4.17.21, 4.17.23 and 4.18.0 each fix one advisory and still sit inside another's range.
	if l := got["lodash@4.17.15"]; l.Fix != "4.18.1" || l.NoFix || len(l.Hits) != 5 {
		t.Errorf("lodash 4.17.15: fix %q nofix %v hits %d", l.Fix, l.NoFix, len(l.Hits))
	}
	if p := got["postcss@8.4.31"]; p.Fix != "8.5.23" || !slices.Equal(p.Files, []string{"a/bun.lock", "b/pnpm-lock.yaml"}) {
		t.Errorf("postcss: fix %q files %v", p.Fix, p.Files)
	}
	if m := got["cxp-jquery@1.0.0"]; m.Fix != "" || !m.NoFix || m.Hits[0].Severity != "critical" || !strings.HasPrefix(m.Hits[0].ID, "MAL-") {
		t.Errorf("a malicious package has no fix but removal: %+v", m)
	}
}

// A flaw that two databases list (GHSA and GO, GHSA and RUSTSEC) is one flaw in the report. Go versions carry a v and
// pseudo-versions order as semver.
func TestGoVersionsAndTheSameFlawInTwoDatabases(t *testing.T) {
	var asked []string
	serve(t, &asked)
	const jwt = "github.com/golang-jwt/jwt/v5"
	out := Scan([]deps.Pkg{{Eco: deps.Go, Name: jwt, Version: "v5.2.1", File: "go.sum"}, {Eco: deps.Go, Name: jwt, Version: "v5.2.2", File: "go.sum"},
		{Eco: deps.Go, Name: "golang.org/x/net", Version: "v0.0.0-20180101000000-abcdefabcdef", File: "go.sum"}}, false, "test")
	if len(out.Vulns) != 2 {
		t.Fatalf("%+v", out.Vulns)
	}
	for _, v := range out.Vulns {
		switch v.Name {
		case jwt:
			if v.Version != "v5.2.1" || len(v.Hits) != 1 || v.Hits[0].ID != "GHSA-mh63-6h87-95cp" || v.Fix != "5.2.2" {
				t.Errorf("jwt: %+v", v)
			}
		default:
			if v.Hits[0].Severity != "high" || v.Fix == "" {
				t.Errorf("a pseudo-version from 2018 is below every fix: %+v", v)
			}
		}
	}
}

func TestRangeBounds(t *testing.T) {
	for _, c := range []struct {
		r       Range
		version string
		want    bool
	}{
		{Range{Introduced: "0", Fixed: "1.0.0"}, "1.0.0-rc.1", true}, // a prerelease sorts below its release
		{Range{Introduced: "0", Fixed: "1.0.0"}, "1.0.0", false},
		{Range{Introduced: "1.2.0", Fixed: "1.2.5"}, "1.1.9", false},
		{Range{Introduced: "1.2.0", Fixed: "1.2.5"}, "v1.2.4", true},
		{Range{Introduced: "0", Last: "2.0.0"}, "2.0.0", true}, // last_affected is inclusive
		{Range{Introduced: "0", Last: "2.0.0"}, "2.0.1", false},
		{Range{Introduced: "0.0.0-0", Fixed: "0.9.5"}, "0.0.1", true},
		{Range{Introduced: "3.0.0"}, "99.0.0", true}, // no fix published
		{Range{Introduced: "not-a-version", Fixed: "2.0.0"}, "1.0.0", false},
	} {
		if got := c.r.Affects(c.version); got != c.want {
			t.Errorf("%+v affects %s = %v, want %v", c.r, c.version, got, c.want)
		}
	}
	// A range that ends at last_affected gives no candidate: the next version is not known.
	if v := Judge("1.0.0", []Range{{ID: "X-1", Introduced: "0", Last: "1.5.0", Severity: "low"}}); !v.NoFix || v.Fix != "" || len(v.Hits) != 1 {
		t.Errorf("%+v", v)
	}
}

// What leaves the machine: the name of an ecosystem's file, once. Never a package, a version or a path.
func TestOnlyTheEcosystemFileIsRequested(t *testing.T) {
	var asked []string
	serve(t, &asked)
	pkgs := []deps.Pkg{
		{Eco: deps.NPM, Name: "@acme/internal-billing", Version: "9.9.9", File: "/home/me/secret-project/bun.lock"},
		{Eco: deps.Cargo, Name: "acme-private-crate", Version: "0.1.0", File: "secret-project/Cargo.lock"},
		{Eco: deps.Go, Name: "git.acme.internal/team/svc", Version: "v1.0.0", File: "secret-project/go.sum"},
	}
	Scan(pkgs, false, "test")
	slices.Sort(asked)
	if want := []string{"/eco-cargo.tsv.gz", "/eco-go.tsv.gz", "/eco-npm.tsv.gz"}; !slices.Equal(asked, want) {
		t.Fatalf("requested %v, want %v", asked, want)
	}
	for _, u := range asked {
		for _, p := range pkgs {
			if strings.Contains(u, p.Name) || strings.Contains(u, "secret-project") || strings.Contains(u, p.Version) {
				t.Errorf("a request names %q: %s", p.Name, u)
			}
		}
	}
}

// With no cache and no network the answer is "no data", never "clean": the caller turns it into exit 3.
func TestOfflineWithoutCacheIsNoDataNotClean(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("RASOAT_LINUX_DATA_URL", "http://127.0.0.1:9/none")
	out := Scan([]deps.Pkg{{Eco: deps.NPM, Name: "lodash", Version: "4.17.15", File: "bun.lock"}}, true, "test")
	if len(out.Vulns) != 0 || out.Checked["npm"] != 0 || !slices.Equal(out.NoData["npm"], []string{"bun.lock"}) {
		t.Errorf("%+v", out)
	}
}

// After one online scan the cache answers a later offline one the same.
func TestOfflineUsesWhatOnlineCached(t *testing.T) {
	var asked []string
	serve(t, &asked)
	pkgs := []deps.Pkg{{Eco: deps.NPM, Name: "postcss", Version: "8.4.31", File: "bun.lock"}}
	online := Scan(pkgs, false, "test")
	n := len(asked)
	offline := Scan(pkgs, true, "test")
	if len(asked) != n || len(offline.Vulns) != 1 || offline.Vulns[0].Fix != online.Vulns[0].Fix || offline.NoData["npm"] != nil {
		t.Errorf("online %+v, offline %+v, requests %v", online, offline, asked)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("XDG_CACHE_HOME"), "rasoat", "linux", "eco-npm.tsv")); err != nil {
		t.Error(err)
	}
}
