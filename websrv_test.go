package main

// Exact versions of nginx, Caddy and Traefik, end to end: image tags in compose files (fixtures/websrv) and vendor packages
// on a machine (internal/linux/testdata/vendor-web-ubuntu2404, a real Ubuntu 24.04 with nginx 1.31.8 from nginx.org and Caddy
// 2.11.4 from Cloudsmith). nginx is judged from the snapshot built into the binary, Caddy and Traefik from the real OSV Go
// rows in fixtures/eco, served over HTTP as the data release serves them.
import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
)

// webData serves the Go ecosystem file and an index. lines is the index's "lines" object, or "" for none.
func webData(t *testing.T, lines string, extra map[string][]byte) map[string]string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if b, ok := extra[name]; ok {
			w.Write(b)
			return
		}
		if name == "index.json" && lines != "" {
			w.Write([]byte(`{"format":1,"built":"2026-11-19","files":{},"lines":` + lines + `}`))
			return
		}
		if b, err := os.ReadFile(filepath.Join("fixtures", "eco", name)); err == nil && strings.HasPrefix(name, "eco-go") {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL, "CACHE": t.TempDir()}
}

func byProduct(rows []rep) map[string]rep {
	out := map[string]rep{}
	for _, r := range rows {
		out[str(r["product"])+" "+str(r["version"])] = r
	}
	return out
}

func advisoryIDs(r rep) []string {
	var ids []string
	for _, a := range r["advisories"].([]any) {
		ids = append(ids, str(a.(rep)["id"]))
	}
	return ids
}

func TestScanJudgesAnExactNginxTag(t *testing.T) {
	code, v := scanJSON(t, fixture("websrv/nginx-vulnerable"), webData(t, "", nil), "--lang=en")
	rows := byProduct(results(v))
	if code != 1 || len(rows) != 2 {
		t.Fatalf("exit %d, rows %v", code, rows)
	}
	r := rows["nginx 1.31.8"]
	if r["status"] != "vulnerable" || r["fix"] != cleanNginx(t, "1.31") || !slices.Contains(advisoryIDs(r), "CVE-2026-123007") || !slices.Contains(advisoryIDs(r), "CVE-2026-123633") {
		t.Errorf("1.31.8: %v", r)
	}
	// -alpine is a variant of the same release; 1.30 is its own branch, fixed on its own branch.
	if r := rows["nginx 1.30.6"]; r["status"] != "vulnerable" || r["fix"] != cleanNginx(t, "1.30") || !strings.Contains(str(r["sources"].([]any)[0]), "nginx:1.30.6-alpine") {
		t.Errorf("1.30.6: %v", r)
	}
}

// cleanNginx is the lowest release of a line that the snapshot's own verdict clears of every advisory: the releases named
// as fixes in the data, tried from the lowest up. It is the data's answer, so a new advisory moves it.
func cleanNginx(t *testing.T, line string) string {
	t.Helper()
	d := data.Bundled().Servers["nginx"]
	var cands []string
	for _, a := range d.Advisories {
		for _, f := range a.Fixed {
			if strings.HasPrefix(f, line+".") && !slices.Contains(cands, f) {
				cands = append(cands, f)
			}
		}
	}
	num := func(v string) []int {
		var out []int
		for _, p := range strings.Split(v, ".") {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	slices.SortFunc(cands, func(a, b string) int { return slices.Compare(num(a), num(b)) })
	for _, c := range cands {
		if r, ok := core.ServerVerdict(c, d); ok && r.Status == core.OK {
			return c
		}
	}
	t.Fatalf("no release of nginx %s is clear of every advisory in the snapshot (fixes named: %v)", line, cands)
	return ""
}

func TestScanFixedNginxTagsAreOk(t *testing.T) {
	// The clean releases are the data's, so the tags are written here and not committed.
	d := t.TempDir()
	write(t, d, "docker-compose.yml", "services:\n  web:\n    image: nginx:"+cleanNginx(t, "1.31")+"\n  edge:\n    image: nginx:"+cleanNginx(t, "1.30")+"-alpine\n")
	code, v := scanJSON(t, d, webData(t, "", nil), "--lang=en")
	if code != 0 {
		t.Fatalf("exit %d: %v", code, v["summary"])
	}
	for k, r := range byProduct(results(v)) {
		if r["status"] != "ok" || r["fix"] != nil {
			t.Errorf("%s: %v", k, r)
		}
	}
}

// A floating tag is not judged by version: the line says so, and so does the row.
func TestScanFloatingWebServerTagsKeepTheLineAnswerAndSayTheyFloat(t *testing.T) {
	lines := `{"nginx":[{"cycle":"1.31","eol":"","latest":"1.31.9"}]}`
	code, v := scanJSON(t, fixture("websrv/nginx-floating"), webData(t, lines, nil), "--lang=en")
	if code != 3 {
		t.Errorf("exit %d", code)
	}
	rows := byProduct(results(v))
	if r := rows["nginx 1.31"]; r["status"] != "unknown" || r["reason"] != "version-not-exact" || !strings.Contains(str(r["how"]), "the tag floats") || !strings.Contains(str(r["how"]), "latest is 1.31.9") {
		t.Errorf("line tag: %v", r)
	}
	if r := rows["nginx "]; r["status"] != "unknown" || r["reason"] != "image-tag-unpinned" || !strings.Contains(str(r["how"]), "the tag floats") {
		t.Errorf("no version: %v", r)
	}
}

func TestScanJudgesAnExactCaddyTagAsItsGoModule(t *testing.T) {
	code, v := scanJSON(t, fixture("websrv/caddy"), webData(t, `{"caddy":[{"cycle":"2.11","eol":"","latest":"2.11.9"}]}`, nil), "--lang=en")
	rows := byProduct(results(v))
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	r := rows["caddy 2.11.4"]
	if r["status"] != "vulnerable" || r["fix"] != "2.11.5" || !slices.Contains(advisoryIDs(r), "GHSA-8qx7-j2v2-x6q5") {
		t.Errorf("2.11.4: %v", r)
	}
	// -alpine and -builder are the same release: one row, three sources.
	if s := r["sources"].([]any); len(s) != 3 {
		t.Errorf("sources %v", s)
	}
	if r := rows["caddy 2.11.9"]; r["status"] != "ok" || r["fix"] != nil {
		t.Errorf("2.11.9: %v", r)
	}
	if r := rows["caddy 2"]; r["status"] != "unknown" || r["reason"] != "version-not-exact" || !strings.Contains(str(r["how"]), "the tag floats") {
		t.Errorf("caddy:2: %v", r)
	}
}

func TestScanJudgesAnExactTraefikTagByItsMajor(t *testing.T) {
	code, v := scanJSON(t, fixture("websrv/traefik"), webData(t, "", nil), "--lang=en")
	rows := byProduct(results(v))
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	// v3.0.4 and 3.0.4 are one release; it reads the /v3 module. v2.10.0 reads the /v2 module: other rows, other fixes.
	r := rows["traefik 3.0.4"]
	if r["status"] != "vulnerable" || len(r["sources"].([]any)) != 2 || r["fix"] == nil || !strings.Contains(str(r["how"]), "traefik/traefik/v3") {
		t.Errorf("3.0.4: %v", r)
	}
	if r := rows["traefik 2.10.0"]; r["status"] != "vulnerable" || !strings.Contains(str(r["how"]), "traefik/traefik/v2") {
		t.Errorf("2.10.0: %v", r)
	}
	if r := rows["traefik 3.0"]; r["status"] != "unknown" {
		t.Errorf("v3.0 floats: %v", r)
	}
}

// With no eco data to be had, an exact Caddy tag is not "ok": the line answers, as before.
func TestScanCaddyWithoutGoDataIsNotClean(t *testing.T) {
	_, v := scanJSON(t, fixture("websrv/caddy"), map[string]string{"RASOAT_LINUX_DATA_URL": "http://127.0.0.1:1"}, "--lang=en")
	if r := byProduct(results(v))["caddy 2.11.9"]; r["status"] != "unknown" {
		t.Errorf("%v", r)
	}
}

func TestScanJudgesAnExactHttpdTag(t *testing.T) {
	code, v := scanJSON(t, fixture("websrv/httpd-vulnerable"), webData(t, "", nil), "--lang=en")
	rows := byProduct(results(v))
	if code != 1 || len(rows) != 1 {
		t.Fatalf("exit %d, rows %v", code, rows)
	}
	// httpd:2.4.70 and httpd:2.4.70-alpine are one release: one row, two sources.
	r := rows["apache-http-server 2.4.70"]
	if r["status"] != "vulnerable" || r["fix"] != "2.4.71" || !slices.Contains(advisoryIDs(r), "CVE-2026-119618") || len(r["sources"].([]any)) != 2 {
		t.Errorf("2.4.70: %v", r)
	}
	// Apache's critical is critical, its important is high.
	sev := map[string]string{}
	for _, a := range r["advisories"].([]any) {
		sev[str(a.(rep)["id"])] = str(a.(rep)["severity"])
	}
	if sev["CVE-2026-119618"] != "critical" || sev["CVE-2026-106023"] != "high" || sev["CVE-2026-109163"] != "low" {
		t.Errorf("severities %v", sev)
	}
}

func TestScanFixedHttpdTagsAreOk(t *testing.T) {
	code, v := scanJSON(t, fixture("websrv/httpd-fixed"), webData(t, "", nil), "--lang=en")
	if code != 0 {
		t.Fatalf("exit %d: %v", code, v["summary"])
	}
	rows := byProduct(results(v))
	if r := rows["apache-http-server 2.4.71"]; len(rows) != 1 || r["status"] != "ok" || r["fix"] != nil {
		t.Errorf("%v", rows)
	}
}

func TestScanFloatingHttpdTagsAskToPinAVersion(t *testing.T) {
	lines := `{"apache-http-server":[{"cycle":"2.4","eol":"","latest":"2.4.71"}]}`
	code, v := scanJSON(t, fixture("websrv/httpd-floating"), webData(t, lines, nil), "--lang=en")
	if code != 3 {
		t.Errorf("exit %d", code)
	}
	rows := byProduct(results(v))
	if r := rows["apache-http-server 2.4"]; r["status"] != "unknown" || r["reason"] != "version-not-exact" || !strings.Contains(str(r["how"]), "pin an exact version") {
		t.Errorf("httpd:2.4: %v", r)
	}
	if r := rows["apache-http-server "]; r["status"] != "unknown" || r["reason"] != "image-tag-unpinned" || len(r["sources"].([]any)) != 2 {
		t.Errorf("httpd:alpine and httpd: %v", r)
	}
}

// A release line that has ended is unsupported even when no advisory in the list reaches the version.
func TestScanEndedHttpdLineIsUnsupported(t *testing.T) {
	d := t.TempDir()
	write(t, d, "docker-compose.yml", "services:\n  web:\n    image: httpd:2.0.65\n")
	lines := `{"apache-http-server":[{"cycle":"2.4","eol":"","latest":"2.4.71"},{"cycle":"2.0","eol":"2013-07-22","latest":"2.0.65"}]}`
	code, v := scanJSON(t, d, webData(t, lines, nil), "--lang=en")
	if r := byProduct(results(v))["apache-http-server 2.0.65"]; code == 0 || r["status"] != "unsupported" || r["fix"] != "2.4.71" {
		t.Errorf("exit %d: %v", code, r)
	}
}

const ubuntuFixes = `{"format":1,"id":"ubuntu-24.04","built":"2026-11-19","records":1}` + "\nnginx\tUSN-1\t1.24.0-2ubuntu7.20\thigh\n"

func webHost(t *testing.T, root string) []rep {
	t.Helper()
	env := webData(t, `{"ubuntu":[{"cycle":"24.04","eol":"2099-05-31"}]}`, map[string][]byte{"ubuntu-24.04.tsv.gz": gz(ubuntuFixes)})
	r := rasoat(t, env["CACHE"], env, "", "host", "--root", root, "--json", "--lang=en")
	return results(parseJSON(t, r.stdout))
}

func TestHostJudgesVendorNginxAndCaddyPackagesAsTheProducts(t *testing.T) {
	rows := byProduct(webHost(t, filepath.Join("internal", "linux", "testdata", "vendor-web-ubuntu2404")))
	n := rows["nginx 1.31.8"]
	if n == nil || n["status"] != "vulnerable" || n["fix"] != cleanNginx(t, "1.31") || !slices.Contains(advisoryIDs(n), "CVE-2026-123007") || !strings.Contains(str(n["how"]), "origin read by apt-lists") {
		t.Errorf("nginx.org build: %v", n)
	}
	c := rows["caddy 2.11.4"]
	if c == nil || c["status"] != "vulnerable" || c["fix"] != "2.11.5" {
		t.Errorf("Caddy build: %v", c)
	}
	for k := range rows {
		if k == "pkg:nginx" || k == "pkg:caddy" {
			t.Errorf("a vendor build was compared with the distro's fixes: %s", k)
		}
	}
}

// Ondrej Sury's Apache build (a real Ubuntu 24.04 with ppa:ondrej/apache2, 2.4.71) is judged as Apache httpd, not against
// the distro's fixes for the apache2 package.
func TestHostJudgesVendorApacheAsTheProduct(t *testing.T) {
	rows := byProduct(webHost(t, filepath.Join("internal", "linux", "testdata", "vendor-httpd-ubuntu2404")))
	r := rows["apache-http-server 2.4.71"]
	if r == nil || r["status"] != "ok" || !strings.Contains(str(r["how"]), "origin read by apt-lists") {
		t.Errorf("Sury build: %v", r)
	}
	for k := range rows {
		if strings.HasPrefix(k, "pkg:apache2") {
			t.Errorf("a vendor build was compared with the distro's fixes: %s", k)
		}
	}
}

// The PPA lists only its newest build, so an older one is no longer in any list: the version marker names the vendor.
// The status here is the real root's, with 2.4.70 written in for 2.4.71 (the one synthetic part of this test).
func TestHostJudgesVendorApacheByItsVersionMarker(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	write(t, root, "var/lib/dpkg/status", "Package: apache2\nStatus: install ok installed\nVersion: 2.4.70-1+ubuntu24.04.1+deb.sury.org+1\n\n"+
		"Package: apache2-bin\nStatus: install ok installed\nSource: apache2\nVersion: 2.4.70-1+ubuntu24.04.1+deb.sury.org+1\n\n")
	r := byProduct(webHost(t, root))["apache-http-server 2.4.70"]
	if r == nil || r["status"] != "vulnerable" || r["fix"] != "2.4.71" || !slices.Contains(advisoryIDs(r), "CVE-2026-119618") {
		t.Errorf("%v", r)
	}
}

// Ubuntu's own apache2 is the distro's: its fixes judge it, whatever number upstream gave the release.
func TestHostKeepsTheDistrosApacheWithTheDistro(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	write(t, root, "var/lib/dpkg/status", "Package: apache2\nStatus: install ok installed\nVersion: 2.4.58-1ubuntu8.5\n\n")
	for _, r := range webHost(t, root) {
		if r["product"] == "apache-http-server" {
			t.Errorf("a distro package was judged by httpd.apache.org's ranges: %v", r)
		}
	}
}

// Ubuntu's own nginx is the distro's: its fixes judge it, whatever number upstream gave the release.
func TestHostKeepsTheDistrosNginxWithTheDistro(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	write(t, root, "var/lib/dpkg/status", "Package: nginx\nStatus: install ok installed\nVersion: 1.24.0-2ubuntu7.19\n\n")
	var found rep
	for _, r := range webHost(t, root) {
		if r["product"] == "pkg:nginx" {
			found = r
		}
		if r["product"] == "nginx" {
			t.Errorf("a distro package was judged by nginx.org's ranges: %v", r)
		}
	}
	if found == nil || found["status"] != "vulnerable" || found["fix"] != "1.24.0-2ubuntu7.20" {
		t.Errorf("%v", found)
	}
}

// The products after nginx and httpd: an exact image tag of each, judged from the snapshot's list for it. Versions are read
// from the data (scripts/websrv/verdict-probe.ts); the tag schemes are Docker Hub's, 2026-11-19.
func TestScanJudgesTheProxyImages(t *testing.T) {
	for _, c := range []struct{ dir, product, version, fix string }{
		{"envoy-vulnerable", "envoy", "1.38.3", "1.38.6"},
		{"envoy-vulnerable", "envoy", "1.37.5", "1.37.8"}, // distroless-v1.37.5
		{"haproxy-vulnerable", "haproxy", "3.2.15", "3.2.26"},
		{"haproxy-vulnerable", "haproxy", "3.4.4", "3.4.7"},
		{"varnish-vulnerable", "varnish", "9.0.3", "9.0.4"},
		{"apache-traffic-server-vulnerable", "apache-traffic-server", "10.2.0", "10.2.1"},
		{"angie-vulnerable", "angie", "1.12.1", "1.12.5"}, // 1.12.5 (2026-11-22) is the release that clears 1.12.1
	} {
		code, v := scanJSON(t, fixture("websrv/"+c.dir), webData(t, "", nil), "--lang=en")
		r := byProduct(results(v))[c.product+" "+c.version]
		if code != 1 || r == nil || r["status"] != "vulnerable" || r["fix"] != c.fix || len(advisoryIDs(r)) == 0 {
			t.Errorf("%s %s %s: exit %d: %v", c.dir, c.product, c.version, code, r)
		}
	}
	for _, d := range []string{"envoy-fixed", "haproxy-fixed", "varnish-fixed", "apache-traffic-server-fixed", "angie-fixed"} {
		code, v := scanJSON(t, fixture("websrv/"+d), webData(t, "", nil), "--lang=en")
		for k, r := range byProduct(results(v)) {
			if code != 0 || r["status"] != "ok" || r["fix"] != nil {
				t.Errorf("%s %s: exit %d: %v", d, k, code, r)
			}
		}
	}
}

// No real OpenResty release has a clean nginx core in the list yet, so the tag is made up from the data's clean nginx
// release plus a patch level. It proves the ok path, nothing more.
func TestScanOpenRestyOnACleanNginxIsOk(t *testing.T) {
	d := t.TempDir()
	write(t, d, "docker-compose.yml", "services:\n  s1:\n    image: openresty/openresty:"+cleanNginx(t, "1.31")+".1-alpine\n")
	code, v := scanJSON(t, d, webData(t, "", nil), "--lang=en")
	for k, r := range byProduct(results(v)) {
		if code != 0 || r["status"] != "ok" || r["fix"] != nil {
			t.Errorf("%s: exit %d: %v", k, code, r)
		}
	}
}

// HAProxy announced two ids before their CVE records carried a rating: the row says unknown, never a guessed band.
func TestScanSaysUnknownSeverityWhereNoneIsPublished(t *testing.T) {
	_, v := scanJSON(t, fixture("websrv/haproxy-vulnerable"), webData(t, "", nil), "--lang=en")
	r := byProduct(results(v))["haproxy 3.2.15"]
	var got []string
	for _, a := range r["advisories"].([]any) {
		got = append(got, str(a.(rep)["id"])+" "+str(a.(rep)["severity"]))
	}
	if !slices.Contains(got, "CVE-2026-78121 unknown") {
		t.Errorf("%v", got)
	}
}

// OpenResty is judged as the nginx it bundles, says so, and offers no nginx release as an OpenResty upgrade.
func TestScanJudgesOpenRestyAsItsBundledNginx(t *testing.T) {
	_, v := scanJSON(t, fixture("websrv/openresty-vulnerable"), webData(t, "", nil), "--lang=en")
	r := byProduct(results(v))["openresty 1.27.1.2"]
	if r == nil || r["status"] != "vulnerable" || r["fix"] != nil || !strings.Contains(str(r["how"]), "judged as its bundled nginx 1.27.1; OpenResty point releases may carry their own patches") || !slices.Contains(advisoryIDs(r), "CVE-2026-123007") {
		t.Errorf("%v", r)
	}
}

// Recognised, with no data: unknown, said plainly, never ok.
func TestScanRecognisedOnlyProductsAreUnknown(t *testing.T) {
	_, v := scanJSON(t, fixture("websrv/recognised-only"), webData(t, "", nil), "--lang=en")
	rows := byProduct(results(v))
	for _, k := range []string{"openlitespeed 1.9.4", "litespeed 6.3.7"} {
		r := rows[k]
		if r == nil || r["status"] != "unknown" || r["reason"] != "no-advisory-data" || !strings.Contains(str(r["how"]), "no advisory data and no release-line data") {
			t.Errorf("%s: %v", k, r)
		}
	}
	for k, r := range rows {
		if r["status"] == "ok" {
			t.Errorf("%s is ok", k)
		}
	}
}

// A line the release data marks ended is unsupported for a family judged only from its release lines (Kong: endoflife.date).
func TestScanEndedKongLineIsUnsupported(t *testing.T) {
	d := t.TempDir()
	write(t, d, "docker-compose.yml", "services:\n  gw:\n    image: kong:2.8.1\n")
	lines := `{"kong-gateway":[{"cycle":"3.9","eol":"","latest":"3.9.4"},{"cycle":"2.8","eol":"2024-03-01","latest":"2.8.5"}]}`
	code, v := scanJSON(t, d, webData(t, lines, nil), "--lang=en")
	if r := byProduct(results(v))["kong-gateway 2.8.1"]; code == 0 || r == nil || r["status"] != "unsupported" || r["fix"] != "3.9.4" {
		t.Errorf("exit %d: %v", code, r)
	}
}

// Vendor builds of four proxies, each from its own repo (a real Ubuntu 24.04 amd64, scripts/linux/proxies-fixture.sh):
// HAProxy from ppa:vbernat/haproxy-3.2, Varnish from packagecloud varnishcache/varnish75, OpenResty from openresty.org,
// Angie from download.angie.software. Each is judged as the product, never against the distro's fixes. The repos list only
// their newest build of a line, so the versions are the ones the repos held on 2026-11-19.
func TestHostJudgesVendorProxyPackagesAsTheProducts(t *testing.T) {
	rows := byProduct(webHost(t, filepath.Join("internal", "linux", "testdata", "vendor-proxies-ubuntu2404")))
	for k, want := range map[string]string{"haproxy 3.2.27": "ok", "angie 1.12.4": "vulnerable", "varnish 7.5.0": "vulnerable", "openresty 1.31.8.1": "vulnerable"} {
		r := rows[k]
		if r == nil || r["status"] != want || !strings.Contains(str(r["how"]), "origin read by apt-lists") {
			t.Errorf("%s: %v", k, r)
		}
	}
	if r := rows["openresty 1.31.8.1"]; r == nil || !strings.Contains(str(r["how"]), "judged as its bundled nginx 1.31.8; OpenResty point releases may carry their own patches") || r["fix"] != nil || !slices.Contains(advisoryIDs(r), "CVE-2026-123007") {
		t.Errorf("OpenResty: %v", r)
	}
	if r := rows["varnish 7.5.0"]; r == nil || !slices.Contains(advisoryIDs(r), "CVE-2025-8671") {
		t.Errorf("Varnish: %v", r)
	}
	// 1.12.4 was clean when this fixture was taken (2026-11-19); the 2026-11-22 list names 1.12.5 as its fix, and a
	// vendor build must follow its own product's list, not stay "ok" because the fixture is old.
	if r := rows["angie 1.12.4"]; r == nil || r["fix"] != "1.12.5" || len(advisoryIDs(r)) == 0 {
		t.Errorf("Angie: %v", r)
	}
	for k := range rows {
		for _, p := range []string{"pkg:haproxy", "pkg:varnish", "pkg:openresty", "pkg:angie"} {
			if strings.HasPrefix(k, p) {
				t.Errorf("a vendor build was compared with the distro's fixes: %s", k)
			}
		}
	}
}

// A distro's own haproxy is the distro's: its fixes judge it, whatever number upstream gave the release.
func TestHostKeepsTheDistrosHaproxyWithTheDistro(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	write(t, root, "var/lib/dpkg/status", "Package: haproxy\nStatus: install ok installed\nVersion: 2.8.16-0ubuntu0.24.04.1\n\n")
	for _, r := range webHost(t, root) {
		if r["product"] == "haproxy" {
			t.Errorf("a distro package was judged by haproxy.org's list: %v", r)
		}
	}
}
