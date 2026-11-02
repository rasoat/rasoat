package main

// The program end to end: itself in a subprocess, real manifests written by their own tools, a real HTTP server.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
	"github.com/rasoat/rasoat/internal/project"
)

func TestMain(m *testing.M) {
	if os.Getenv("RASOAT_TEST_SELF") == "1" {
		os.Exit(run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const nowhere = "http://127.0.0.1:9/none"

type out struct {
	code   int
	stdout string
	stderr string
}

func rasoat(t *testing.T, cache string, env map[string]string, stdin string, args ...string) out {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	vars := map[string]string{"RASOAT_TEST_SELF": "1", "XDG_CACHE_HOME": cache, "RASOAT_DATA_URL": nowhere, "LC_ALL": "", "LC_MESSAGES": "", "LANG": "en_US.UTF-8"}
	for k, v := range env {
		vars[k] = v
	}
	cmd.Env = os.Environ()
	for k, v := range vars {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out{code, so.String(), se.String()}
}

type rep = map[string]any

func scanJSON(t *testing.T, target string, env map[string]string, extra ...string) (int, rep) {
	t.Helper()
	if extra == nil {
		extra = []string{"--offline"}
	}
	cache := t.TempDir()
	if env != nil && env["CACHE"] != "" {
		cache = env["CACHE"]
	}
	r := rasoat(t, cache, env, "", append([]string{"scan", target, "--json"}, extra...)...)
	var v rep
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s\n%s", err, r.stdout, r.stderr)
	}
	return r.code, v
}

func fixture(name string) string { return filepath.Join("fixtures", name) }

func write(t *testing.T, root, path, text string) {
	t.Helper()
	file := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lock(version string) string {
	return fmt.Sprintf(`{"lockfileVersion":3,"packages":{"node_modules/next":{"version":%q}}}`, version)
}

func versions(w project.Walked) []string {
	out := []string{}
	for _, f := range w.Found {
		out = append(out, f.Version)
	}
	slices.Sort(out)
	return out
}

func results(r rep) []rep {
	out := []rep{}
	for _, x := range r["results"].([]any) {
		out = append(out, x.(rep))
	}
	return out
}

func TestManifestsAsEachToolWritesThem(t *testing.T) {
	for _, c := range [][3]string{{"npm", "next", "14.2.3"}, {"pnpm", "next", "13.5.11"}, {"bun", "next", "15.0.0"}, {"yarn-v1", "next", "12.3.7"}, {"yarn-berry", "next", "16.0.0"}, {"wordpress", "wordpress", "6.4.3"}, {"bedrock", "wordpress", "6.5.2"}} {
		w := project.Walk(fixture(c[0]))
		if len(w.Found) != 1 || w.Found[0].Product != c[1] || w.Found[0].Version != c[2] {
			t.Errorf("%s: %+v", c[0], w.Found)
		}
	}
	w := project.Walk(fixture("pins"))
	got := []string{}
	for _, f := range w.Found {
		got = append(got, f.Product+" "+f.Version)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"bun 1.1.0", "node 18.12.0", "php 8.1"}) {
		t.Errorf("pins: %v", got)
	}
}

func TestOtherNamesAreNotNext(t *testing.T) {
	m := project.Manifests
	for name, text := range map[string]string{
		"pnpm-lock.yaml":    "  next-auth@4.0.0:\n  /next-seo@6.0.0:\n",
		"yarn.lock":         "next-auth@^4:\n  version \"4.0.0\"\n",
		"bun.lock":          `"next-auth": ["next-auth@4.0.0", ""]`,
		"package-lock.json": `{"packages":{"node_modules/next-auth":{"version":"4.0.0"}}}`,
	} {
		if got := m[name](text); len(got) != 0 {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestParsersOnBadInput(t *testing.T) {
	got := project.WpVersionPhp("/* $wp_version = '9.9'; */\n$wp_version = '6.4.3';\n")
	if len(got) != 1 || got[0].Version != "6.4.3" {
		t.Errorf("commented-out $wp_version: %v", got)
	}
	if len(project.Manifests["package-lock.json"]("{ not json")) != 0 || len(project.Manifests["composer.lock"]("")) != 0 {
		t.Error("malformed files must say nothing")
	}
}

func TestWalk(t *testing.T) {
	pkg := func(next string) string { return fmt.Sprintf(`{"dependencies":{"next":%q}}`, next) }
	t.Run("a range beside no lockfile is reported as declared, not guessed", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "package.json", pkg("^14.0.0"))
		if v := versions(project.Walk(d)); !slices.Equal(v, []string{"^14.0.0"}) {
			t.Error(v)
		}
	})
	t.Run("a workspace's range is answered by the root lockfile", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "bun.lock", `"next": ["next@15.0.0", ""],`)
		write(t, d, "apps/web/package.json", pkg("^15.0.0"))
		if v := versions(project.Walk(d)); !slices.Equal(v, []string{"15.0.0"}) {
			t.Error(v)
		}
	})
	t.Run("scanning inside a monorepo finds the lockfile above", func(t *testing.T) {
		d := t.TempDir()
		os.Mkdir(filepath.Join(d, ".git"), 0o755)
		write(t, d, "bun.lock", `"next": ["next@15.0.0", ""],`)
		write(t, d, "apps/web/package.json", pkg("^15.0.0"))
		w := project.Walk(filepath.Join(d, "apps", "web"))
		if len(w.Found) != 1 || w.Found[0].Version != "15.0.0" || w.Found[0].Path != "../../bun.lock" {
			t.Errorf("%+v", w.Found)
		}
	})
	t.Run("finds several sites under one folder", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "client-a/wp-includes/version.php", "$wp_version = '6.4.3';\n")
		write(t, d, "client-b/package-lock.json", lock("14.2.3"))
		if v := versions(project.Walk(d)); !slices.Equal(v, []string{"14.2.3", "6.4.3"}) {
			t.Error(v)
		}
	})
	t.Run("skips dependencies, build output and wp-content; reads the installed version", func(t *testing.T) {
		d := t.TempDir()
		for _, s := range []string{"vendor", "dist", "wp-content/plugins/x", ".next", "node_modules/foo"} {
			write(t, d, s+"/package-lock.json", lock("9.0.0"))
		}
		write(t, d, "node_modules/next/package.json", `{"name":"next","version":"14.2.3"}`)
		if v := versions(project.Walk(d)); !slices.Equal(v, []string{"14.2.3"}) {
			t.Error(v)
		}
	})
	t.Run("follows no symlink out of the project", func(t *testing.T) {
		d, outside := t.TempDir(), t.TempDir()
		write(t, outside, "package-lock.json", lock("9.0.0"))
		if err := os.Symlink(outside, filepath.Join(d, "linked")); err != nil {
			t.Skip("no symlinks here")
		}
		os.Symlink(filepath.Join(outside, "package-lock.json"), filepath.Join(d, "package-lock.json"))
		if v := project.Walk(d).Found; len(v) != 0 {
			t.Error(v)
		}
	})
	t.Run("says when a binary lockfile could not be read", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "bun.lockb", "\x00\x00")
		if !slices.Contains(project.Walk(d).Notes, "binary-bun-lock") {
			t.Error("no note")
		}
	})
}

func TestVerdictsAndExitCodes(t *testing.T) {
	t.Run("vulnerable: exit 1, the fix clears every advisory, sources relative", func(t *testing.T) {
		code, r := scanJSON(t, fixture("npm"), nil)
		x := results(r)[0]
		if code != 1 || r["exit_code"].(float64) != 1 || x["product"] != "next" || x["version"] != "14.2.3" || x["status"] != "vulnerable" || x["sources"].([]any)[0] != "package-lock.json" {
			t.Fatalf("%d %v", code, x)
		}
		if x["advisories"].([]any)[0].(rep)["severity"] != "critical" {
			t.Error("worst first")
		}
		fix := x["fix"].(string)
		v := core.VerdictFor("next", &fix, data.Bundled(), "2026-11-02")
		if v.Status != core.OK {
			t.Errorf("fix %s is itself %s", fix, v.Status)
		}
	})
	t.Run("WordPress verdict follows WordPress.org, fix stays on the branch", func(t *testing.T) {
		_, r := scanJSON(t, fixture("wordpress"), nil)
		x := results(r)[0]
		if x["status"] != "vulnerable" || !strings.HasPrefix(x["fix"].(string), "6.4.") {
			t.Error(x)
		}
		if data.Bundled().WordPress.Stable[x["fix"].(string)] == "insecure" {
			t.Error("fix is insecure")
		}
	})
	t.Run("clean: exit 0 only when every version is judged clean", func(t *testing.T) {
		_, first := scanJSON(t, fixture("npm"), nil)
		d := t.TempDir()
		write(t, d, "package-lock.json", lock(results(first)[0]["fix"].(string)))
		code, r := scanJSON(t, d, nil)
		if code != 0 || r["summary"].(rep)["ok"].(float64) != 1 || !slices.Contains(r["not_checked"].([]any), any("wordpress-plugins-themes")) {
			t.Error(code, r["summary"])
		}
	})
	t.Run("a range cannot be judged: exit 3, reason given", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "package.json", `{"dependencies":{"next":"^14.0.0"}}`)
		code, r := scanJSON(t, d, nil)
		x := results(r)[0]
		if code != 3 || x["status"] != "unknown" || x["reason"] != "version-not-exact" {
			t.Error(code, x)
		}
	})
	t.Run("partial runtime pin is not treated as x.y.0", func(t *testing.T) {
		_, r := scanJSON(t, fixture("pins"), nil)
		for _, x := range results(r) {
			if x["product"] == "php" && (x["version"] != "8.1" || x["status"] != "unknown") {
				t.Error(x)
			}
		}
	})
	t.Run("an end-of-life line with no listed hit is unsupported, exit 1", func(t *testing.T) {
		s := data.Bundled()
		eol := "2000-01-01"
		snap := *s
		rt := snap.Runtimes["php"]
		snap.Runtimes = map[string]core.RtData{"php": {ID: "php", Branches: []core.RtBranch{{Cycle: "1.2", EOL: &eol, Latest: "1.2.3"}}, Vulns: []core.RtVuln{}}, "node": rt, "bun": rt}
		v := "1.2.3"
		if got := core.VerdictFor("php", &v, &snap, "2026-11-02"); got.Status != core.Unsupported {
			t.Error(got.Status)
		}
	})
	t.Run("a version number too long to hold is judged, not a crash", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, ".nvmrc", strings.Repeat("9", 60)+".0.0\n")
		code, r := scanJSON(t, d, nil)
		if code != 3 || results(r)[0]["status"] != "unknown" {
			t.Error(code, r["results"])
		}
	})
	t.Run("nothing identified is not a pass: exit 3", func(t *testing.T) {
		code, r := scanJSON(t, t.TempDir(), nil)
		if code != 3 || len(results(r)) != 0 {
			t.Error(code)
		}
	})
	t.Run("usage errors: exit 2", func(t *testing.T) {
		for _, a := range [][]string{{"scan", "/no/such/place"}, {"frobnicate"}, {"scan", ".", "--lang", "fr"}, {}, {"scan", ".", "--nope"}} {
			if r := rasoat(t, t.TempDir(), nil, "", a...); r.code != 2 {
				t.Error(a, r.code)
			}
		}
	})
	t.Run("scanning writes nothing into the project", func(t *testing.T) {
		d := t.TempDir()
		write(t, d, "package-lock.json", lock("14.2.3"))
		rasoat(t, t.TempDir(), nil, "", "scan", d, "--offline")
		entries, _ := os.ReadDir(d)
		if len(entries) != 1 {
			t.Error(entries)
		}
	})
	t.Run("terminal view: both languages, the coverage limit and the notices", func(t *testing.T) {
		en := rasoat(t, t.TempDir(), nil, "", "scan", fixture("npm"), "--offline").stdout
		for _, s := range []string{"VULNERABLE", "Not checked: WordPress plugins", "This product uses the NVD API but is not endorsed or certified by the NVD.", "Vercel, the Vercel design, Next.js"} {
			if !strings.Contains(en, s) {
				t.Error(s)
			}
		}
		vi := rasoat(t, t.TempDir(), map[string]string{"LANG": "vi_VN.UTF-8"}, "", "scan", fixture("npm"), "--offline").stdout
		for _, s := range []string{"CÓ LỖ HỔNG", "nâng lên"} {
			if !strings.Contains(vi, s) {
				t.Error(s)
			}
		}
	})
	t.Run("help and version", func(t *testing.T) {
		if r := rasoat(t, t.TempDir(), nil, "", "--version"); r.code != 0 || !regexp.MustCompile(`^\d+\.\d+\.\d+\n$`).MatchString(r.stdout) {
			t.Error(r)
		}
		if r := rasoat(t, t.TempDir(), nil, "", "--help"); r.code != 0 || !strings.Contains(r.stdout, "NVD") {
			t.Error(r)
		}
	})
}

// The bundled snapshot as a download, changed as a test needs.
func snapshotJSON(t *testing.T, change func(rep)) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("internal", "data", "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s rep
	json.Unmarshal(b, &s)
	s["built"] = "2099-01-01"
	if change != nil {
		change(s)
	}
	out, _ := json.Marshal(s)
	return out
}

func TestTheSnapshotAScanAnswersFrom(t *testing.T) {
	serve := func(t *testing.T, body []byte, status int) (*httptest.Server, *int, *string) {
		hits, ua := 0, ""
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			ua = r.Header.Get("User-Agent")
			w.WriteHeader(status)
			w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return srv, &hits, &ua
	}
	addAdvisory := func(s rep) {
		next := s["next"].(rep)
		advisories := next["advisories"].([]any)
		a := map[string]any{}
		for k, v := range advisories[0].(rep) {
			a[k] = v
		}
		a["ghsa"] = "GHSA-test-test-test"
		a["ranges"] = []any{rep{"vulnerable": ">= 1.0.0", "patched": nil}}
		next["advisories"] = append(advisories, a)
	}
	t.Run("a newer snapshot decides the verdict, one plain GET, cached for the next run", func(t *testing.T) {
		srv, hits, ua := serve(t, snapshotJSON(t, addAdvisory), 200)
		env := map[string]string{"RASOAT_DATA_URL": srv.URL + "/data/snapshot-v1.json", "CACHE": t.TempDir()}
		_, a := scanJSON(t, fixture("npm"), env, "--json")
		d := a["data"].(rep)
		x := results(a)[0]
		if d["origin"] != "downloaded" || d["built"] != "2099-01-01" || x["noFix"] != true || *hits != 1 || !strings.HasPrefix(*ua, "rasoat-cli/") {
			t.Error(d, x["noFix"], *hits, *ua)
		}
		ids := []string{}
		for _, adv := range x["advisories"].([]any) {
			ids = append(ids, adv.(rep)["id"].(string))
		}
		if !slices.Contains(ids, "GHSA-test-test-test") {
			t.Error("the new advisory is not in the verdict")
		}
		_, b := scanJSON(t, fixture("npm"), env, "--json")
		if b["data"].(rep)["origin"] != "cached" || *hits != 1 {
			t.Error(b["data"], *hits)
		}
	})
	t.Run("--offline sends nothing", func(t *testing.T) {
		srv, hits, _ := serve(t, snapshotJSON(t, nil), 200)
		_, r := scanJSON(t, fixture("npm"), map[string]string{"RASOAT_DATA_URL": srv.URL})
		if r["data"].(rep)["origin"] != "bundled" || *hits != 0 {
			t.Error(r["data"], *hits)
		}
	})
	type refusal struct {
		name    string
		body    []byte
		status  int
		problem string
	}
	for _, c := range []refusal{
		{"malformed JSON", []byte("<html>"), 200, "invalid"},
		{"wrong shape", snapshotJSON(t, func(s rep) { s["next"] = rep{"advisories": []any{rep{"ghsa": 1}}} }), 200, "invalid"},
		{"unknown format", snapshotJSON(t, func(s rep) { s["format"] = 2 }), 200, "invalid"},
		{"older data", snapshotJSON(t, func(s rep) { s["built"] = "2020-01-01" }), 200, "older"},
		{"records gone (would call everything clean)", snapshotJSON(t, func(s rep) { s["next"].(rep)["advisories"] = []any{} }), 200, "lost-records"},
		{"server error", []byte("no"), 500, "unreachable"},
	} {
		t.Run("refused: "+c.name+": keeps the built-in data and says so", func(t *testing.T) {
			srv, _, _ := serve(t, c.body, c.status)
			cache := t.TempDir()
			code, r := scanJSON(t, fixture("npm"), map[string]string{"RASOAT_DATA_URL": srv.URL, "CACHE": cache}, "--json")
			d := r["data"].(rep)
			if d["origin"] != "bundled" || d["problem"] != c.problem || code != 1 {
				t.Error(d, code)
			}
			if _, err := os.Stat(filepath.Join(cache, "rasoat")); err == nil {
				t.Error("a refused download reached the cache")
			}
		})
	}
	t.Run("a corrupted cache is ignored", func(t *testing.T) {
		cache := t.TempDir()
		write(t, cache, "rasoat/snapshot-v1.json", "{ nope")
		_, r := scanJSON(t, fixture("npm"), map[string]string{"CACHE": cache})
		if r["data"].(rep)["origin"] != "bundled" {
			t.Error(r["data"])
		}
	})
	t.Run("old data carries a warning", func(t *testing.T) {
		_, r := scanJSON(t, fixture("npm"), nil)
		built, _ := time.Parse("2006-01-02", data.Bundled().Built)
		days := int(time.Since(built) / (24 * time.Hour))
		d := r["data"].(rep)
		if int(d["age_days"].(float64)) != days || d["stale"] != (days > 7) {
			t.Error(d, days)
		}
	})
	t.Run("control sequences in advisory text never reach the terminal", func(t *testing.T) {
		evil := "\u001b]0;pwned\u0007\u001b[2Jpoison\u009b31m"
		body := snapshotJSON(t, func(s rep) {
			for _, a := range s["next"].(rep)["advisories"].([]any) {
				a.(rep)["summary"] = evil + a.(rep)["summary"].(string)
			}
		})
		srv, _, _ := serve(t, body, 200)
		env := map[string]string{"RASOAT_DATA_URL": srv.URL}
		human := rasoat(t, t.TempDir(), env, "", "scan", fixture("npm")).stdout
		ctl := regexp.MustCompile("[\u001b\u0007\u009b]")
		if !strings.Contains(human, "poison") || ctl.MatchString(human) {
			t.Errorf("%q", human[:200])
		}
		js := rasoat(t, t.TempDir(), env, "", "scan", fixture("npm"), "--json").stdout
		if ctl.MatchString(js) {
			t.Error("control characters in --json")
		}
		var r rep
		json.Unmarshal([]byte(js), &r)
		if !strings.Contains(results(r)[0]["advisories"].([]any)[0].(rep)["summary"].(string), evil) {
			t.Error("the text must survive JSON intact")
		}
	})
	t.Run("the notices are the program's own, whatever a download says", func(t *testing.T) {
		srv, _, _ := serve(t, snapshotJSON(t, func(s rep) { s["notices"] = []any{"Sponsored by nobody"} }), 200)
		_, r := scanJSON(t, fixture("npm"), map[string]string{"RASOAT_DATA_URL": srv.URL}, "--json")
		if slices.Contains(r["notices"].([]any), any("Sponsored by nobody")) {
			t.Error("a download changed the notices")
		}
	})
}

func TestScanningASite(t *testing.T) {
	t.Run("bot protection is reported, not fought: one request, exit 3", func(t *testing.T) {
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(403)
		}))
		defer srv.Close()
		code, r := scanJSON(t, srv.URL+"/", nil)
		s := r["site"].(rep)
		if hits != 1 || code != 3 || s["outcome"] != "blocked" || s["status"].(float64) != 403 || s["by"] != "Cloudflare" {
			t.Error(hits, code, s)
		}
	})
	t.Run("unreachable: exit 3 with the cause", func(t *testing.T) {
		code, r := scanJSON(t, "http://127.0.0.1:9/", nil)
		if s := r["site"].(rep); code != 3 || s["outcome"] != "unreachable" || s["cause"] != "network" {
			t.Error(code, s)
		}
	})
	t.Run("a redirect loop stops", func(t *testing.T) {
		hits := 0
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			http.Redirect(w, r, fmt.Sprintf("%s/%d", srv.URL, hits), http.StatusFound)
		}))
		defer srv.Close()
		_, r := scanJSON(t, srv.URL+"/", nil)
		if r["site"].(rep)["outcome"] != "unreachable" || hits > 6 {
			t.Error(r["site"], hits)
		}
	})
	t.Run("a site without a recognised framework: exit 3, nothing claimed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>hi</html>") }))
		defer srv.Close()
		code, r := scanJSON(t, srv.URL+"/", nil)
		if code != 3 || len(results(r)) != 0 {
			t.Error(code)
		}
	})
	t.Run("a WordPress page, its version from the generator, the runtime as a bound", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><meta name="generator" content="WordPress 6.4.3"><link href="/wp-content/x.css"></html>`)
		}))
		defer srv.Close()
		_, r := scanJSON(t, srv.URL+"/", nil)
		x := results(r)[0]
		if x["product"] != "wordpress" || x["version"] != "6.4.3" || x["how"] != "generator meta" {
			t.Error(x)
		}
		if notes := r["notes"].([]any); len(notes) != 1 || !strings.HasPrefix(notes[0].(string), "php-min:") {
			t.Error(notes)
		}
	})
	t.Run("a Next.js page: scripts in order, the version from the bootstrap", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_next/static/chunks/main-abc.js" {
				fmt.Fprint(w, `foo;window.next={version:"14.2.3",appDir:!0};bar`)
				return
			}
			fmt.Fprint(w, `<html><script src="/_next/static/chunks/main-abc.js"></script><script src="/other.js"></script></html>`)
		}))
		defer srv.Close()
		code, r := scanJSON(t, srv.URL+"/", nil)
		x := results(r)[0]
		if code != 1 || x["version"] != "14.2.3" || x["how"] != "window.next.version" {
			t.Error(code, x)
		}
	})
}

func TestBinaryPathIsNotInOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path form differs")
	}
	wd, _ := os.Getwd()
	if r := rasoat(t, t.TempDir(), nil, "", "--help"); strings.Contains(r.stdout, wd) {
		t.Error("help carries the build path")
	}
}
