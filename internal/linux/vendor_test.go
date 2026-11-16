package linux

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
)

// testdata/vendor-ubuntu2404 is a real Ubuntu 24.04 with the Sury PHP PPA, PGDG and NodeSource, trimmed by
// scripts/linux/vendor-fixture.sh. Its php8.3 is 8.3.36-1+ubuntu24.04.1+deb.sury.org+1.
const vendorRoot = "testdata/vendor-ubuntu2404"

const vendorIndex = `{"format":1,"built":"2026-11-02","files":{"ubuntu-24.04":1},"lines":{"ubuntu":[{"cycle":"24.04","eol":"2029-05-31"}],"postgresql":[{"cycle":"18","latest":"18.7"},{"cycle":"16","latest":"16.16","eol":"2028-11-09"},{"cycle":"13","latest":"13.23","eol":"2025-11-13"}]}}`

// ubuntuFixes carries what the distro published for php8.3: a fix far below Sury's number. Before the origin was read, this
// made the fixture's php8.3 a silent "clean" (8.3.36 sorts above 8.3.6): pkg:php8.3 was judged, as ok, against Ubuntu's fixes.
const ubuntuFixes = `{"format":1,"id":"ubuntu-24.04","built":"2026-11-02","records":2}` + "\nphp8.3\tUSN-1\t8.3.6-0ubuntu0.24.04.2\thigh\nglibc\tUSN-2\t99:2.39-1\thigh\n"

func vendorScan(t *testing.T, root string, snapshots *int) *Host {
	t.Helper()
	cacheData(t, map[string]string{"index.json": vendorIndex, "ubuntu-24.04.tsv": ubuntuFixes})
	h, err := Scan(Options{Root: root, Offline: true, UserAgent: "t", Today: "2026-11-02", Snapshot: func() *core.Snapshot {
		*snapshots++
		return nil // a snapshot is not what is tested here: that the question is asked, and only for PHP and Node
	}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func vendorRow(h *Host, product, version string) *Finding {
	for i := range h.Findings {
		if h.Findings[i].Product == product && h.Findings[i].Version != nil && *h.Findings[i].Version == version {
			return &h.Findings[i]
		}
	}
	return nil
}

func checkVendorRows(t *testing.T, h *Host, method string) {
	t.Helper()
	for _, f := range h.Findings {
		if strings.HasPrefix(f.Product, "pkg:php") || strings.HasPrefix(f.Product, "pkg:postgresql") || strings.HasPrefix(f.Product, "pkg:nodejs") {
			t.Errorf("a vendor build was compared with the distro's fixes: %s", f.Product)
		}
	}
	php := vendorRow(h, "php", "8.3.36")
	if php == nil || !slices.Contains(php.Installed, "php8.3-cli") || !strings.Contains(php.How, "origin read by "+method) {
		t.Fatalf("php %+v", php)
	}
	if node := vendorRow(h, "node", "22.23.5"); node == nil || !slices.Equal(node.Installed[:1], []string{"nodejs"}) {
		t.Fatalf("node %+v", node)
	}
	// libpq5 is PGDG's postgresql-18; the client is postgresql-16: two lines, judged by release line, never by distro fix.
	if pg := vendorRow(h, "postgresql", "16.16"); pg == nil || !slices.Contains(pg.Installed, "postgresql-client-16") || pg.Status != core.Unknown {
		t.Fatalf("pg16 %+v", pg)
	}
	if pg := vendorRow(h, "postgresql", "18.7"); pg == nil || !slices.Contains(pg.Installed, "libpq5") {
		t.Fatalf("pg18 %+v", pg)
	}
	if h.Packages != 221 {
		t.Errorf("packages %d", h.Packages)
	}
	if find(h, "pkg:glibc") == nil {
		t.Error("the distro's own packages are still judged")
	}
}

func TestVendorBuildsAreReadFromAptLists(t *testing.T) {
	n := 0
	h := vendorScan(t, vendorRoot, &n)
	checkVendorRows(t, h, "apt-lists")
	if n != 1 {
		t.Errorf("snapshot loaded %d times: once, for PHP and Node together", n)
	}
	// What no row routes is counted, per origin, and never reads as clean.
	if !slices.Contains(h.Notes, "vendor-not-judged:LP-PPA-ondrej-php:1") || !slices.Contains(h.Notes, "vendor-not-judged:apt.postgresql.org:1") {
		t.Errorf("%v", h.Notes)
	}
	// The row without a snapshot says so, rather than ok.
	if php := vendorRow(h, "php", "8.3.36"); php.Status != core.Unknown || *php.Reason != "no-advisory-data" {
		t.Errorf("%+v", php)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(to), 0o755)
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// With no lists (a docker image keeps them compressed, or a minimal root has none), the version strings decide.
func TestVendorBuildsFallBackToVersionMarkers(t *testing.T) {
	root := t.TempDir()
	copyFile(t, filepath.Join(vendorRoot, "etc/os-release"), filepath.Join(root, "etc/os-release"))
	copyFile(t, filepath.Join(vendorRoot, "var/lib/dpkg/status"), filepath.Join(root, "var/lib/dpkg/status"))
	n := 0
	h := vendorScan(t, root, &n)
	checkVendorRows(t, h, "version-marker")
}

func TestListsOfAnotherVersionDecideNothing(t *testing.T) {
	// The installed version is no longer listed anywhere, and has no marker: the distro is assumed, as before.
	pkgs := []Package{{Name: "php8.3-cli", Version: "8.3.1-1ubuntu1"}, {Name: "x", Version: "1.0+pmx2"}}
	root := t.TempDir()
	copyFile(t, filepath.Join(vendorRoot, "var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease"), filepath.Join(root, "var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease"))
	copyFile(t, filepath.Join(vendorRoot, "var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_main_binary-arm64_Packages"), filepath.Join(root, "var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_main_binary-arm64_Packages"))
	assignOrigins(root, "deb", pkgs)
	if pkgs[0].Vendor != "" || pkgs[0].Decided != "" {
		t.Errorf("%+v", pkgs[0])
	}
	if pkgs[1].Vendor != "proxmox" || pkgs[1].Decided != "version-marker" {
		t.Errorf("%+v", pkgs[1])
	}
}

// A list with no release file cannot say whose it is, and a compressed one cannot be read: neither decides.
func TestUnpairedAndCompressedListsDecideNothing(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/apt/lists")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "example.org_dists_noble_main_binary-amd64_Packages"), []byte("Package: a\nVersion: 1\n\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "example.org_dists_noble_main_binary-amd64_Packages.lz4"), []byte("x"), 0o644)
	pkgs := []Package{{Name: "a", Version: "1"}}
	assignOrigins(root, "deb", pkgs)
	if pkgs[0].Decided != "" {
		t.Errorf("%+v", pkgs[0])
	}
}

func TestBackportsAreNotTheDistrosSecurityData(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/apt/lists")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "m.example_ubuntu_dists_noble-backports_InRelease"), []byte("Origin: Ubuntu\nSuite: noble-backports\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "m.example_ubuntu_dists_noble-backports_main_binary-amd64_Packages"), []byte("Package: b\nVersion: 2\n\nPackage: c\nVersion: 3\n\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "m.example_ubuntu_dists_noble-updates_InRelease"), []byte("Origin: Ubuntu\nSuite: noble-updates\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "m.example_ubuntu_dists_noble-updates_main_binary-amd64_Packages"), []byte("Package: c\nVersion: 3\n\n"), 0o644)
	pkgs := []Package{{Name: "b", Version: "2"}, {Name: "c", Version: "3"}}
	assignOrigins(root, "deb", pkgs)
	if pkgs[0].Vendor != "Ubuntu backports" {
		t.Errorf("%+v", pkgs[0])
	}
	if pkgs[1].Vendor != "" || pkgs[1].Decided != "apt-lists" {
		t.Errorf("a version the distro's own pocket lists is the distro's: %+v", pkgs[1])
	}
}

func TestUpstreamVersionAndRouting(t *testing.T) {
	for in, want := range map[string]string{
		"1:11.8.9+maria~ubu2404":                "11.8.9",
		"16.16-1.pgdg24.04+1":                   "16.16",
		"8.3.27-1+ubuntu24.04.1+deb.sury.org+1": "8.3.27",
		"22.23.4-1nodesource1":                  "22.23.4",
		"16.4-1PGDG.rhel9":                      "16.4",
		"weird":                                 "",
	} {
		if got := upstreamVersion(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	for _, c := range []struct{ key, source, want string }{
		{"sury", "php8.3", "php"}, {"sury", "php-defaults", ""}, {"remi", "php", "php"}, {"nodesource", "nodejs", "node"},
		{"pgdg", "postgresql-16", "postgresql"}, {"pgdg", "postgresql16", "postgresql"}, {"pgdg", "pgbouncer", ""},
		{"mariadb", "mariadb", "mariadb"}, {"mariadb", "mariadb-10.11", "mariadb"}, {"", "php8.3", ""}, {"proxmox", "pve-manager", ""},
	} {
		if got := vendorProduct(c.key, c.source); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
	// MariaDB's own repo, with an epoch: judged by release line, with no lines loaded it says so.
	rows, notes, _ := judgeVendors([]Package{
		{Name: "mariadb-server", Version: "1:11.8.9+maria~ubu2404", Source: "mariadb", SourceVersion: "1:11.8.9+maria~ubu2404", Vendor: "mariadb", Decided: "version-marker"},
		{Name: "docker-ce", Version: "5:27.0-1~ubuntu", Source: "docker-ce", SourceVersion: "5:27.0-1~ubuntu", Vendor: "Docker", Decided: "apt-lists"},
	}, nil, Options{Today: "2026-11-02"})
	if len(rows) != 1 || rows[0].Product != "mariadb" || *rows[0].Version != "11.8.9" || *rows[0].Reason != "line-data-not-available" {
		t.Fatalf("%+v", rows)
	}
	if !slices.Equal(notes, []string{"vendor-not-judged:Docker:1"}) {
		t.Errorf("%v", notes)
	}
}

func TestRpmVendor(t *testing.T) {
	for in, want := range map[string]struct {
		vendor  string
		decided bool
	}{
		"Red Hat, Inc.":                        {"", true},
		"Rocky Enterprise Software Foundation": {"", true},
		"SUSE LLC <https://www.suse.com/>":     {"", true},
		"PostgreSQL Global Development Group":  {"PostgreSQL Global Development Group", true},
		"Remi's RPM repository":                {"Remi's RPM repository", true},
		"(none)":                               {"", false},
		"":                                     {"", false},
	} {
		if v, ok := rpmVendor(in); v != want.vendor || ok != want.decided {
			t.Errorf("%q: %q %v", in, v, ok)
		}
	}
	if vendorKey("PostgreSQL Global Development Group") != "pgdg" || vendorKey("Remi's RPM repository") != "remi" {
		t.Error("rpm vendors route like apt origins")
	}
}
