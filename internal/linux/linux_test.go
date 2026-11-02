package linux

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
)

func gunzip(t *testing.T, file string) []byte {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var rpmFormats = map[string]func([]byte) ([][]byte, error){"sqlite": readSQLite, "bdb": readBDB, "ndb": readNDB}

// Each file is a real database from a real image; the .txt beside it is what rpm itself listed (scripts/linux/rpmdb-fixtures.sh).
func TestRpmDatabasesEqualWhatRpmLists(t *testing.T) {
	for name, read := range rpmFormats {
		t.Run(name, func(t *testing.T) {
			blobs, err := read(gunzip(t, "testdata/rpmdb/"+name+".gz"))
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, b := range blobs {
				if p, ok := parseHeader(b); ok {
					got = append(got, fmt.Sprintf("%s %s %s-%s.src.rpm", p.Name, p.Version, p.Source, stripEpoch(p.SourceVersion)))
				}
			}
			slices.Sort(got)
			text, err := os.ReadFile("testdata/rpmdb/" + name + ".txt")
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Split(strings.TrimSpace(string(text)), "\n")
			slices.Sort(want)
			if len(want) < 50 {
				t.Fatalf("a real database has more than %d packages", len(want))
			}
			if !slices.Equal(got, want) {
				for i := range min(len(got), len(want)) {
					if got[i] != want[i] {
						t.Fatalf("first difference: %q, rpm says %q (%d, %d)", got[i], want[i], len(got), len(want))
					}
				}
				t.Fatalf("%d packages, rpm lists %d", len(got), len(want))
			}
		})
	}
}

func stripEpoch(v string) string {
	_, r := splitEpoch(v)
	return r
}

// A database comes from the machine being judged: a damaged or hostile one must say nothing, never crash or hang.
func TestBrokenDatabasesSayNothing(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for name, read := range rpmFormats {
		good := gunzip(t, "testdata/rpmdb/"+name+".gz")
		for try := range 300 {
			bad := bytes.Clone(good)
			switch try % 3 {
			case 0:
				bad = bad[:rng.Intn(len(bad))]
			case 1:
				for range 200 {
					bad[rng.Intn(min(len(bad), 8192))] = byte(rng.Intn(256))
				}
			case 2:
				for range 2000 {
					bad[rng.Intn(len(bad))] = byte(rng.Intn(256))
				}
			}
			blobs, _ := read(bad)
			for _, b := range blobs {
				parseHeader(b)
			}
		}
		for try := range 100 {
			b := make([]byte, rng.Intn(4096))
			rng.Read(b)
			if try%2 == 0 {
				copy(b, "SQLite format 3\x00")
			}
			parseHeader(b)
			read(b)
		}
	}
}

func TestDpkgStatus(t *testing.T) {
	status := `Package: libgcc-s1
Status: install ok installed
Architecture: amd64
Source: gcc-12 (12.2.0-14)
Version: 12.2.0-14+deb12u1
Description: a
 continuation Version: 9
Package-Thing: no

Package: gone
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Version: 5.2.15-2+b2

`
	got := parseDpkg([]byte(status), nil)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if p := got[0]; p.Source != "gcc-12" || p.SourceVersion != "12.2.0-14" || p.Version != "12.2.0-14+deb12u1" {
		t.Errorf("%+v", p)
	}
	if p := got[1]; p.Source != "bash" || p.SourceVersion != "5.2.15-2+b2" {
		t.Errorf("%+v", p)
	}
}

func TestKernelVersionAgainstARealRecord(t *testing.T) {
	// kernel.org's own record of CVE-2024-26581: in from 6.5, fixed on lines 5.4, 5.10, 5.15, 6.1, 6.6, 6.7, and from 6.8.
	c := KernelCVE{ID: "CVE-2024-26581", Introduced: "6.5", Unaffected: []string{"5.4.269:5.4.*", "5.10.210:5.10.*", "5.15.149:5.15.*", "6.1.78:6.1.*", "6.6.17:6.6.*", "6.7.5:6.7.*", "6.8:*"}}
	for v, want := range map[string]bool{
		"6.6.16": true, "6.6.17": false, "6.6.100": false, "6.5": true, "6.5.13": true, "6.7.4": true, "6.7.5": false,
		"6.8": false, "6.8.1": false, "7.3.1": false, "6.4": false, "4.19.300": false, "6.1.78": false,
	} {
		if got := c.Affected(v); got != want {
			t.Errorf("%s = %v", v, got)
		}
	}
	// A line older than the introduction, and a backport below it.
	back := KernelCVE{Introduced: "5.0", Unaffected: []string{"5.10.210:5.10.*", "5.15.149:<5.15.200"}}
	for v, want := range map[string]bool{"4.19.1": false, "5.10.209": true, "5.10.210": false, "5.15.149": false, "5.15.200": true, "5.15.148": true} {
		if got := back.Affected(v); got != want {
			t.Errorf("back %s = %v", v, got)
		}
	}
}

func TestOnlyAPlainKernelIsJudgedByItsNumber(t *testing.T) {
	for v, want := range map[string]bool{
		"6.6.30": true, "6.12": true, "6.13-rc1": true, "6.6.30+": true,
		"6.8.0-45-generic": false, "5.14.0-427.13.1.el9_4.x86_64": false, "5.15.90.1-microsoft-standard-WSL2": false, "6.1.0-25-amd64": false, "6.6.31-0-lts": false, "6.4.0-150600.23.25-default": false,
	} {
		if IsPlainKernel(v) != want {
			t.Errorf("%s", v)
		}
	}
}

func TestKernelImageAndSource(t *testing.T) {
	for _, c := range []struct {
		family                   string
		p                        Package
		isImage                  bool
		uname, source, sourceVer string
	}{
		{"deb", Package{Name: "linux-image-6.1.0-25-amd64", Version: "6.1.106-3", Source: "linux-signed-amd64", SourceVersion: "6.1.106+3"}, true, "6.1.0-25-amd64", "linux", "6.1.106-3"},
		{"deb", Package{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45", Source: "linux-signed", SourceVersion: "6.8.0-45.45"}, true, "6.8.0-45-generic", "linux", "6.8.0-45.45"},
		{"deb", Package{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45~22.04.1", Source: "linux-signed-hwe-6.8", SourceVersion: "6.8.0-45.45~22.04.1"}, true, "6.8.0-45-generic", "linux-hwe-6.8", "6.8.0-45.45~22.04.1"},
		{"deb", Package{Name: "linux-image-generic", Version: "6.8.0.45", Source: "linux-meta", SourceVersion: "6.8.0.45"}, false, "", "linux-meta", "6.8.0.45"},
		{"rpm", Package{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4", Source: "kernel", SourceVersion: "5.14.0-427.13.1.el9_4"}, true, "5.14.0-427.13.1.el9_4", "kernel", "5.14.0-427.13.1.el9_4"},
		{"rpm", Package{Name: "kernel-default", Version: "6.4.0-150600.23.103.1", Source: "kernel-default", SourceVersion: "6.4.0-150600.23.103.1"}, true, "6.4.0-150600.23.103-default", "kernel-default", "6.4.0-150600.23.103.1"},
		{"apk", Package{Name: "linux-lts", Version: "6.6.31-r0", Source: "linux-lts", SourceVersion: "6.6.31-r0"}, true, "6.6.31-0-lts", "linux-lts", "6.6.31-r0"},
	} {
		isImage, uname := kernelImage(c.family, c.p)
		src, ver := kernelSource(c.family, c.p)
		if isImage != c.isImage || uname != c.uname || src != c.source || ver != c.sourceVer {
			t.Errorf("%s: %v %q %q %q", c.p.Name, isImage, uname, src, ver)
		}
	}
	if !kernelMatches("rpm", Package{Name: "kernel-core", Version: "5.14.0-427.el9"}, "5.14.0-427.el9.x86_64") {
		t.Error("the running rpm kernel adds its architecture")
	}
}

func TestModularFixesStayOnTheirStream(t *testing.T) {
	plain := Package{Version: "8.0.30-1.el9"}
	php81 := Package{Version: "8.1.20-1.module_el9.2+1", Stream: "8.1"}
	node18 := Package{Version: "18.16.0-1.module+el8", Stream: "18"}
	for _, c := range []struct {
		p     Package
		fixed string
		want  bool
	}{
		{plain, "8.1.32-1.module_el9.8.0+326", false},
		{php81, "8.0.30-1.el9", false},
		{php81, "8.2.1-1.module_el9.3+2", false},
		{php81, "8.1.32-1.module_el9.8.0+326", true},
		{php81, "1:8.1.32-1.module_el9.8.0+326", true},
		{node18, "18.20.2-1.module+el8.1", true},
		{node18, "20.11.0-1.module+el8.1", false},
		{plain, "8.0.31-1.el9", true},
		{Package{Version: "5.14.0-687.61.1.el9_8"}, "0:5.14.0-687.61.1.el9_8.cloud.1.0", false},
		{Package{Version: "5.14.0-687.36.1.el9_8.cloud.1.0"}, "0:5.14.0-687.61.1.el9_8.cloud.1.0", true},
	} {
		if got := moduleOK(c.p, c.fixed); got != c.want {
			t.Errorf("%+v vs %s = %v", c.p, c.fixed, got)
		}
	}
}

func TestUpgradeCommandTakesOnlyPlainNames(t *testing.T) {
	got := upgradeCommand("deb", []string{"openssl", "libssl3", "evil; curl x | sh", "$(reboot)", "libstdc++6"})
	if got != "apt-get update && apt-get install --only-upgrade libssl3 libstdc++6 openssl" {
		t.Error(got)
	}
	if upgradeCommand("rpm", []string{"; rm"}) != "" {
		t.Error("nothing plain, no command")
	}
}

func TestPickReadsOnlyWhatIsWanted(t *testing.T) {
	lines := "curl\tDSA-1\t8.0-1\thigh\ncurl\t\t\t3\nvim\tDSA-2\t9.0-1\tlow\nbroken line\n"
	a := PickAdvisories([]byte(lines), map[string]bool{"curl": true})
	if len(a.Fixed["curl"]) != 1 || a.Open["curl"] != 3 || a.Fixed["vim"] != nil {
		t.Errorf("%+v", a)
	}
}

func hostRoot(t *testing.T, osRelease, statusFile, status string) string {
	t.Helper()
	root := t.TempDir()
	for path, text := range map[string]string{"etc/os-release": osRelease, statusFile: status} {
		file := filepath.Join(root, path)
		os.MkdirAll(filepath.Dir(file), 0o755)
		if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func cacheData(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	for name, text := range files {
		file := filepath.Join(dir, "rasoat", "linux", name)
		os.MkdirAll(filepath.Dir(file), 0o755)
		if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const index = `{"format":1,"built":"2026-11-02","files":{"debian-12":3},"lines":{"debian":[{"cycle":"13","eol":"2030-06-30"},{"cycle":"12","eol":"2028-06-30","latest":"12.9"},{"cycle":"11","eol":"2026-08-31","extended":"2031-06-30"}],"linux":[{"cycle":"7.3","latest":"7.3.1"},{"cycle":"6.6","latest":"6.6.161","eol":"2028-12-31"},{"cycle":"6.5","latest":"6.5.13","eol":"2023-11-28"}]}}`

func find(h *Host, product string) *Finding {
	for i := range h.Findings {
		if h.Findings[i].Product == product {
			return &h.Findings[i]
		}
	}
	return nil
}

func TestHost(t *testing.T) {
	head := `{"format":1,"id":"debian-12","built":"2026-11-02","records":4}` + "\n"
	cacheData(t, map[string]string{
		"index.json": index,
		"debian-12.tsv": head + "openssl\tDSA-5\t3.0.11-1~deb12u1\thigh\nopenssl\tDSA-1\t3.0.2-1\tlow\nopenssl\t\t\t7\nbash\tDSA-9\t5.0-1\tlow\n" +
			"linux\tDSA-7\t6.1.112-1\thigh\n" + "gcc-12\tDSA-8\t12.2.0-14\tmedium\n",
		"linux-kernel.tsv": `{"format":1,"id":"linux-kernel","built":"2026-11-02","records":1}` + "\nCVE-2024-26581\t6.5\t6.6.17:6.6.*,6.8:*\n",
	})
	osr := `ID=debian` + "\n" + `VERSION_ID="12"` + "\n" + `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"` + "\n"
	stanza := func(name, version, source string) string {
		s := "Package: " + name + "\nStatus: install ok installed\nVersion: " + version + "\n"
		if source != "" {
			s += "Source: " + source + "\n"
		}
		return s + "\n"
	}
	status := stanza("libssl3", "3.0.2-1", "openssl") + stanza("openssl", "3.0.2-1", "") + stanza("bash", "5.2-1", "") +
		stanza("libgcc-s1", "12.2.0-14+deb12u1", "gcc-12 (12.2.0-14)") +
		stanza("linux-image-6.1.0-25-amd64", "6.1.106-3", "linux-signed-amd64 (6.1.106+3)") + stanza("linux-image-6.1.0-21-amd64", "6.1.90-1", "linux-signed-amd64 (6.1.90+1)") +
		stanza("linux-libc-dev", "6.1.0-1", "linux")
	root := hostRoot(t, osr, "var/lib/dpkg/status", status)
	scan := func(kernel string) *Host {
		h, err := Scan(Options{Root: root, Kernel: kernel, Offline: true, UserAgent: "t", Today: "2026-11-02"})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := scan("")
	if h.Packages != 7 || find(h, "debian").Status != core.OK {
		t.Errorf("%d %+v", h.Packages, find(h, "debian"))
	}
	ssl := find(h, "pkg:openssl")
	if ssl == nil || ssl.Status != core.Vulnerable || *ssl.Fix != "3.0.11-1~deb12u1" || len(ssl.Advisories) != 1 || !slices.Equal(ssl.Installed, []string{"libssl3", "openssl"}) {
		t.Fatalf("%+v", ssl)
	}
	if find(h, "pkg:bash") != nil {
		t.Error("bash is above its fix")
	}
	if find(h, "pkg:gcc-12") != nil {
		t.Error("a binary's rebuild suffix must not hide or invent a source version: gcc-12 is at its fix")
	}
	if find(h, "pkg:linux") != nil {
		t.Error("kernel packages are judged once, as the kernel, not as a package")
	}
	if h.Open != 7 {
		t.Errorf("open %d", h.Open)
	}
	if h.UpgradeCmd != "apt-get update && apt-get install --only-upgrade libssl3 openssl" {
		t.Error(h.UpgradeCmd)
	}

	// With no kernel named on a mounted root: the newest installed is what would boot.
	k := find(h, "linux")
	if k == nil || k.Status != core.Vulnerable || *k.Version != "6.1.0-25-amd64" || *k.Fix != "6.1.112-1" {
		t.Fatalf("%+v", k)
	}
	if h.Newest != "6.1.0-25-amd64" || h.Reboot {
		t.Errorf("newest %s reboot %v", h.Newest, h.Reboot)
	}

	// A named kernel that is the older of two installed: judged as that one, by its package.
	older := find(scan("6.1.0-21-amd64"), "linux")
	if older == nil || !strings.Contains(older.How, "linux-image-6.1.0-21-amd64") {
		t.Fatalf("%+v", older)
	}

	// A kernel no package explains and that is plain: the number decides, from kernel.org's record.
	up := find(scan("6.6.16"), "linux")
	if up.Status != core.Vulnerable || up.Advisories[0].ID != "CVE-2024-26581" || *up.Fix != "6.6.161" {
		t.Errorf("%+v", up)
	}
	if clean := find(scan("6.6.17"), "linux"); clean.Status != core.OK {
		t.Errorf("%+v", clean)
	}
	if ended := find(scan("6.8.5"), "linux"); ended.Status != core.OK || *ended.Version != "6.8.5" {
		t.Errorf("%+v", ended)
	}
	if ended := find(scan("6.5.13"), "linux"); ended.Status != core.Vulnerable || *ended.Fix != "6.6.161" {
		t.Errorf("an ended line moves to the next one alive: %+v", ended)
	}

	// A vendor's build no package explains: its number says nothing.
	vendor := find(scan("5.15.90.1-microsoft-standard-WSL2"), "linux")
	if vendor.Status != core.Unknown || *vendor.Reason != "vendor-kernel" {
		t.Errorf("%+v", vendor)
	}
}

func TestHostWithoutDataSaysSo(t *testing.T) {
	cacheData(t, map[string]string{})
	root := hostRoot(t, "ID=debian\nVERSION_ID=\"12\"\n", "var/lib/dpkg/status", "Package: a\nStatus: install ok installed\nVersion: 1\n\n")
	h, err := Scan(Options{Root: root, Offline: true, UserAgent: "t"})
	if err != nil {
		t.Fatal(err)
	}
	p := find(h, "packages")
	if p == nil || p.Status != core.Unknown || *p.Reason != "package-data-not-available" || find(h, "debian").Status != core.Unknown {
		t.Errorf("%+v", h)
	}
}

func TestEndOfLife(t *testing.T) {
	cacheData(t, map[string]string{"index.json": index})
	root := hostRoot(t, "ID=debian\nVERSION_ID=\"11\"\n", "var/lib/dpkg/status", "")
	h, err := Scan(Options{Root: root, Offline: true, UserAgent: "t", Today: "2026-11-02"})
	if err != nil {
		t.Fatal(err)
	}
	d := find(h, "debian")
	if d.Status != core.Unsupported || *d.Fix != "13" || !slices.Contains(h.Notes, "paid-extended-support-until:2031-06-30") {
		t.Errorf("%+v %v", d, h.Notes)
	}
}

func TestDistroMapping(t *testing.T) {
	for _, c := range []struct{ text, file, line, family string }{
		{"ID=ubuntu\nVERSION_ID=\"22.04\"", "ubuntu-22.04", "22.04", "deb"},
		{"ID=debian\nVERSION_ID=\"12\"", "debian-12", "12", "deb"},
		{"ID=\"almalinux\"\nVERSION_ID=\"9.4\"", "almalinux-9", "9", "rpm"},
		{"ID=\"rocky\"\nVERSION_ID=\"8.10\"", "rocky-8", "8", "rpm"},
		{"ID=\"rhel\"\nVERSION_ID=\"9.2\"", "rhel-9", "9", "rpm"},
		{"ID=alpine\nVERSION_ID=3.20.1", "alpine-3.20", "3.20", "apk"},
		{"ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"", "opensuse-leap-15.6", "15.6", "rpm"},
		{"ID=\"sles\"\nVERSION_ID=\"15.5\"", "sles-15.5", "15.5", "rpm"},
		{"ID=\"centos\"\nVERSION_ID=\"7\"", "", "7", "rpm"},
		{"ID=arch\n", "", "", ""},
		{"ID=linuxmint\nVERSION_ID=\"21\"\nID_LIKE=ubuntu", "", "", ""},
	} {
		root := hostRoot(t, c.text+"\n", "x", "")
		d := DetectDistro(root)
		if d.File != c.file || d.Line != c.line || d.Family != c.family {
			t.Errorf("%q: %+v", c.text, d)
		}
	}
	if DetectDistro(t.TempDir()) != nil {
		t.Error("no os-release, no distro")
	}
}

func TestAMountedImageCannotReadOutsideItself(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("PRETTY_NAME=stolen\nID=debian\nVERSION_ID=\"12\"\n"), 0o644)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	if err := os.Symlink(secret, filepath.Join(root, "etc/os-release")); err != nil {
		t.Skip("no symlinks here")
	}
	if d := DetectDistro(root); d != nil {
		t.Errorf("read through a symlink out of the image: %+v", d)
	}
	// The usual relative link inside the image still works.
	os.Remove(filepath.Join(root, "etc/os-release"))
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("ID=debian\n"), 0o644)
	os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release"))
	if d := DetectDistro(root); d == nil || d.ID != "debian" {
		t.Errorf("%+v", d)
	}
}
