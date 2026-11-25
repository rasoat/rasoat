package linux

// A tree under examination can be hostile: these build one in a temporary directory and check that reading it stays inside
// it, stays cheap, and does not fall over.
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	baseOSRelease = "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
	baseStatus    = "Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n"
)

func hostileRoot(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return hostRoot(t, baseOSRelease, "var/lib/dpkg/status", baseStatus)
}

func scanOffline(t *testing.T, root string) *Host {
	t.Helper()
	h, err := Scan(Options{Root: root, Offline: true, UserAgent: "t", Today: "2026-11-02"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func needSymlinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
}

// machineFile is a file of the machine the test runs on, for proof that none of it reaches a report. "": not readable here.
func machineFile(t *testing.T, path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 8 {
		return ""
	}
	return strings.SplitN(string(b), "\n", 2)[0]
}

func TestSymlinkedStatusDoesNotReadTheMachine(t *testing.T) {
	needSymlinks(t)
	for _, target := range []string{"/etc/shadow", "/etc/passwd", "../../../../etc/passwd"} {
		t.Run(target, func(t *testing.T) {
			root := hostileRoot(t)
			status := filepath.Join(root, "var/lib/dpkg/status")
			os.Remove(status)
			if err := os.Symlink(target, status); err != nil {
				t.Fatal(err)
			}
			h := scanOffline(t, root)
			if h.Packages != 0 {
				t.Errorf("%d packages from a link out of the tree", h.Packages)
			}
			out, _ := json.Marshal(h)
			for _, f := range []string{"/etc/passwd", "/etc/shadow"} {
				if line := machineFile(t, f); line != "" && strings.Contains(string(out), line) {
					t.Errorf("content of %s in the result", f)
				}
			}
		})
	}
}

func TestSymlinkedStatusDEntryIsNotRead(t *testing.T) {
	needSymlinks(t)
	root := hostileRoot(t)
	dir := filepath.Join(root, "var/lib/dpkg/status.d")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "good"), []byte("Package: zlib\nStatus: install ok installed\nVersion: 1.2-1\n\n"), 0o644)
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../../etc/passwd", filepath.Join(dir, "evil2")); err != nil {
		t.Fatal(err)
	}
	if h := scanOffline(t, root); h.Packages != 2 { // status and the good entry
		t.Errorf("%d packages", h.Packages)
	}
}

func TestDockerenvSymlinkIsNotFollowed(t *testing.T) {
	needSymlinks(t)
	root := hostileRoot(t)
	if err := os.Symlink("/etc", filepath.Join(root, ".dockerenv")); err != nil {
		t.Fatal(err)
	}
	if h := scanOffline(t, root); !h.InContainer {
		t.Error("a marker that is a link is still there")
	}
	if existsIn(root, "no/such/file") {
		t.Error("exists")
	}
}

func TestOversizeFilesAreRefusedBySize(t *testing.T) {
	root := hostileRoot(t)
	dir := filepath.Join(root, "var/lib/dpkg/status.d")
	os.MkdirAll(dir, 0o755)
	big := "Package: zlib\nStatus: install ok installed\nVersion: 1.2-1\nX-Pad: " + strings.Repeat("a", maxDpkgEntry) + "\n\n"
	os.WriteFile(filepath.Join(dir, "big"), []byte(big), 0o644)
	if h := scanOffline(t, root); h.Packages != 1 {
		t.Errorf("a status.d file over its cap was read: %d packages", h.Packages)
	}
	os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(baseOSRelease+"X="+strings.Repeat("a", maxSmallText)+"\n"), 0o644)
	if _, err := Scan(Options{Root: root, Offline: true, UserAgent: "t"}); err != ErrNotLinux {
		t.Errorf("an os-release over its cap was read: %v", err)
	}
}

func TestSparseStatusIsRefusedFast(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a sparse file is not cheap everywhere on windows")
	}
	root := hostileRoot(t)
	status := filepath.Join(root, "var/lib/dpkg/status")
	if err := os.Truncate(status, 2<<30); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	h := scanOffline(t, root)
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}
	if h.Packages != 0 {
		t.Errorf("%d packages", h.Packages)
	}
}

func TestHugeAptListDirectoryIsCutWithANote(t *testing.T) {
	root := hostileRoot(t)
	lists := filepath.Join(root, "var/lib/apt/lists")
	os.MkdirAll(lists, 0o755)
	for i := range 100_000 {
		f, err := os.Create(filepath.Join(lists, fmt.Sprintf("f%06d", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	start := time.Now()
	h := scanOffline(t, root)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	found := false
	for _, n := range h.Notes {
		found = found || n == tooManyFiles
	}
	if !found {
		t.Errorf("no note: %v", h.Notes)
	}
}

func TestNonUTF8FieldsDoNotPanic(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := hostRoot(t, "ID=debian\nVERSION_ID=\"12\xff\"\nPRETTY_NAME=\"De\xc3bian \xe2\x28\xa1\"\n", "var/lib/dpkg/status",
		"Package: ba\xffsh\nStatus: install ok installed\nVersion: 5.\xc32-1\nSource: s\xfe (1\x80)\n\n")
	h := scanOffline(t, root)
	if _, err := json.Marshal(h); err != nil {
		t.Error(err)
	}
	if h.Packages != 1 {
		t.Errorf("%d packages", h.Packages)
	}
}

// A crafted rpm database must not make the reader loop or allocate in proportion to anything but the file's own size.
func TestSQLiteOverflowCycleIsCut(t *testing.T) {
	const page = 512
	d := &sqliteDB{data: make([]byte, 200*page), pageSize: page, usable: page, seen: map[uint32]bool{}}
	d.data[page+3] = 2                                                   // page 2 names page 2 as its next
	cell := append([]byte{0x86, 0x8d, 0x20, 0x01}, make([]byte, 432)...) // payload of 100000 bytes, 432 local, then the next page
	cell = append(cell, 0, 0, 0, 2)
	start := time.Now()
	if got := d.cellPayload(cell); got != nil {
		t.Errorf("a cyclic overflow chain gave %d bytes", len(got))
	}
	if time.Since(start) > time.Second {
		t.Error("slow")
	}
}

func TestSQLiteInteriorPageCycleIsCut(t *testing.T) {
	data := make([]byte, 1024)
	copy(data, "SQLite format 3\x00")
	data[16], data[17] = 0x02, 0x00 // page size 512
	data[100] = 0x05                // interior table page
	data[103], data[104] = 0, 1     // one cell
	data[108+3] = 1                 // right-most child: page 1 again
	data[112], data[113] = 0, 200   // the cell, at 200: child page 1 again
	data[203] = 1
	start := time.Now()
	if _, err := readSQLite(data); err != errFormat {
		t.Errorf("%v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("slow")
	}
}

func TestBDBOverflowCycleIsCut(t *testing.T) {
	const page = 512
	data := make([]byte, 8*page)
	copy(data[12:], []byte{0x61, 0x15, 0x06, 0x00}) // little-endian magic 0x061561
	data[20], data[21] = 0, 2                       // page size 512
	data[32] = 3                                    // last page
	p := data[page:]
	p[25] = 2                     // a hash page
	p[20] = 2                     // two entries: a key, a value
	p[26+2], p[26+3] = 0x40, 0x00 // the value, at 64: off-page
	p[64] = 3
	p[64+4] = 2                   // first overflow page: 2
	p[64+8], p[64+9] = 0x00, 0x10 // total 4096
	o := data[2*page:]
	o[25] = 7
	o[22] = 4 // 4 bytes used
	o[16] = 2 // next: itself
	start := time.Now()
	blobs, err := readBDB(data)
	if err != nil || len(blobs) != 0 {
		t.Errorf("%v %d", err, len(blobs))
	}
	if time.Since(start) > time.Second {
		t.Error("slow")
	}
}
