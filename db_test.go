package main

// `rasoat db status` and `rasoat db update`: the local vulnerability database, end to end against a real HTTP server.
import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// dbServer serves the index, the ecosystem files of fixtures/eco, one distro file and the snapshot. Each can be
// swapped for a test's own body; every request path is recorded.
type dbServer struct {
	URL   string
	mu    sync.Mutex
	asked []string
	body  map[string][]byte
}

func newDBServer(t *testing.T) *dbServer {
	t.Helper()
	s := &dbServer{body: map[string][]byte{}}
	s.body["/index.json"] = []byte(`{"format":1,"built":"2099-01-01","files":{"eco-cargo":4,"eco-go":4,"eco-npm":4,"debian-12":7,"linux-kernel":9},"lines":{}}`)
	for _, f := range []string{"eco-cargo", "eco-go", "eco-npm"} {
		b, err := os.ReadFile(filepath.Join("fixtures", "eco", f+".tsv.gz"))
		if err != nil {
			t.Fatal(err)
		}
		s.body["/"+f+".tsv.gz"] = b
	}
	s.body["/debian-12.tsv.gz"] = gz(`{"format":1,"id":"debian-12","built":"2099-01-01","records":7}` + "\nopenssl\tDSA-1\t3.0.1\tHIGH\n")
	s.body["/linux-kernel.tsv.gz"] = gz(`{"format":1,"id":"linux-kernel","built":"2099-01-01","records":9}` + "\nCVE-1\t5.0\t\n")
	s.body["/snapshot"] = snapshotJSON(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.asked = append(s.asked, r.URL.Path)
		b, ok := s.body[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

func (s *dbServer) env() map[string]string {
	return map[string]string{"RASOAT_LINUX_DATA_URL": s.URL, "RASOAT_DATA_URL": s.URL + "/snapshot"}
}

func (s *dbServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.asked)
	slices.Sort(out)
	return out
}

func dbJSON(t *testing.T, cache string, env map[string]string, args ...string) (int, rep) {
	t.Helper()
	r := rasoat(t, cache, env, "", append([]string{"db"}, append(args, "--json")...)...)
	var v rep
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s\n%s", err, r.stdout, r.stderr)
	}
	return r.code, v
}

func files(v rep) map[string]rep {
	out := map[string]rep{}
	for _, f := range v["files"].([]any) {
		out[f.(rep)["name"].(string)] = f.(rep)
	}
	return out
}

func TestDbStatusReadsTheCacheAndSendsNothing(t *testing.T) {
	s := newDBServer(t)
	cache := t.TempDir()
	code, v := dbJSON(t, cache, s.env(), "status")
	f := files(v)
	if code != 0 || v["schema"] != 1.0 || v["kind"] != "db_status" || len(f) != 5 {
		t.Fatalf("%d %v", code, v)
	}
	if f["snapshot-v1.json"]["origin"] != "bundled" || f["index.json"]["origin"] != "none" || f["eco-npm.tsv.gz"]["origin"] != "none" {
		t.Errorf("an empty cache: %v", f)
	}
	if f["eco-npm.tsv.gz"]["age_days"] != nil || f["eco-npm.tsv.gz"]["stale"] != false {
		t.Errorf("a file that is not there has no age: %v", f["eco-npm.tsv.gz"])
	}
	if p := f["eco-npm.tsv.gz"]["path"].(string); !strings.HasPrefix(p, cache) {
		t.Errorf("path %s is not in the cache", p)
	}
	if len(s.requests()) != 0 {
		t.Errorf("status sent %v", s.requests())
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("status wrote to the cache: %v", entries)
	}
}

func TestDbUpdateFillsTheCacheNamingOnlyFiles(t *testing.T) {
	s := newDBServer(t)
	cache := t.TempDir()
	code, v := dbJSON(t, cache, s.env(), "update")
	if code != 0 || v["kind"] != "db_update" || v["failed"] != 0.0 {
		t.Fatalf("%d %v", code, v)
	}
	for name, c := range files(v) {
		if c["result"] != "added" || c["problem"] != nil {
			t.Errorf("%s: %v", name, c)
		}
	}
	// the snapshot, the index, and the three ecosystems: no distro file without --all, and never a package or a project
	if want := []string{"/eco-cargo.tsv.gz", "/eco-go.tsv.gz", "/eco-npm.tsv.gz", "/index.json", "/snapshot"}; !slices.Equal(s.requests(), want) {
		t.Errorf("requested %v", s.requests())
	}
	_, st := dbJSON(t, cache, s.env(), "status")
	f := files(st)
	if f["eco-npm.tsv.gz"]["origin"] != "cached" || f["eco-npm.tsv.gz"]["records"].(float64) < 1 || f["index.json"]["built"] != "2099-01-01" || f["snapshot-v1.json"]["origin"] != "cached" {
		t.Errorf("after the update: %v", f)
	}
	// a second update names the same files and changes nothing
	_, again := dbJSON(t, cache, s.env(), "update")
	for name, c := range files(again) {
		if c["result"] != "unchanged" {
			t.Errorf("%s: %v", name, c)
		}
	}
}

func TestDbUpdateAllFetchesEveryDistroFileAndSaysHowManyFirst(t *testing.T) {
	s := newDBServer(t)
	cache := t.TempDir()
	r := rasoat(t, cache, s.env(), "", "db", "update", "--all")
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	plan := strings.Index(r.stdout, "Also downloading 2 distro release files (16 records")
	first := strings.Index(r.stdout, "snapshot-v1.json")
	if plan < 0 || first < 0 {
		t.Fatalf("no plan line:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "debian-12.tsv.gz") || !strings.Contains(r.stdout, "linux-kernel.tsv.gz") {
		t.Errorf("distro files not listed:\n%s", r.stdout)
	}
	_, st := dbJSON(t, cache, s.env(), "status")
	f := files(st)
	if f["debian-12.tsv.gz"]["kind"] != "distro" || f["debian-12.tsv.gz"]["origin"] != "cached" || f["linux-kernel.tsv.gz"]["kind"] != "kernel" {
		t.Errorf("status lists each cached distro file: %v", f)
	}
	// the distro file is what `rasoat host --root` would have downloaded: it is held to the same checks
	if !slices.Contains(s.requests(), "/debian-12.tsv.gz") {
		t.Errorf("requested %v", s.requests())
	}
}

func TestDbUpdateKeepsAFileThatWouldGoBackwards(t *testing.T) {
	s := newDBServer(t)
	cache := t.TempDir()
	dbJSON(t, cache, s.env(), "update")
	older := gz(`{"format":1,"id":"eco-cargo","built":"2000-01-01","records":99999}` + "\n")
	s.mu.Lock()
	s.body["/eco-cargo.tsv.gz"] = older
	delete(s.body, "/eco-go.tsv.gz") // and one that does not come at all
	s.mu.Unlock()
	code, v := dbJSON(t, cache, s.env(), "update")
	f := files(v)
	if code != 2 || v["failed"] != 2.0 {
		t.Errorf("a refused download is an error: %d %v", code, v)
	}
	if c := f["eco-cargo.tsv.gz"]; c["result"] != "kept" || c["problem"] != "older" {
		t.Errorf("%v", c)
	}
	if c := f["eco-go.tsv.gz"]; c["result"] != "kept" || c["problem"] != "unreachable" {
		t.Errorf("%v", c)
	}
	_, st := dbJSON(t, cache, s.env(), "status")
	if b := files(st)["eco-cargo.tsv.gz"]["built"]; b == "2000-01-01" {
		t.Errorf("the older file replaced the newer: %v", b)
	}
}

func TestOfflineAfterDbUpdateJudgesWhatOnlineJudged(t *testing.T) {
	s := newDBServer(t)
	cache := t.TempDir()
	if r := rasoat(t, cache, s.env(), "", "db", "update"); r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	// no server at all now: --offline reads the cache the update filled
	gone := map[string]string{"CACHE": cache, "RASOAT_LINUX_DATA_URL": nowhere, "RASOAT_DATA_URL": nowhere}
	code, offline := scanJSON(t, fixture("cargo"), gone, "--offline", "--lang=en")
	fresh := s.env()
	fresh["CACHE"] = t.TempDir() // a scan with nothing cached downloads what it needs
	_, online := scanJSON(t, fixture("cargo"), fresh, "--lang=en")
	if code != 1 || len(results(offline)) != 1 || results(offline)[0]["product"] != "pkg:cargo/tokio" {
		t.Fatalf("exit %d: %v", code, results(offline))
	}
	offline["data"], online["data"] = nil, nil
	a, _ := json.Marshal(offline)
	b, _ := json.Marshal(online)
	if !bytes.Equal(a, b) {
		t.Errorf("offline and online differ:\n%s\n%s", a, b)
	}
}
