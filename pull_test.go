package main

// The pull script: what it sends must give the same answer as the whole tree, in less.
import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The script sits in public/scripts here, and in scripts at the top of the published tree.
func hostFilesScript(t *testing.T) string {
	t.Helper()
	for _, p := range []string{filepath.Join("public", "scripts", "host-files.sh"), filepath.Join("scripts", "host-files.sh")} {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Fatal("host-files.sh not found")
	return ""
}

func needPullTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a POSIX script")
	}
	for _, tool := range []string{"sh", "tar", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool, "is not installed")
		}
	}
}

// pull runs the script on root, in an empty working directory that must stay empty, and returns the tar.
func pull(t *testing.T, root string) []byte {
	t.Helper()
	script := hostFilesScript(t)
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	cmd := exec.Command("sh", script, root)
	cmd.Dir = cwd
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v\n%s", err, se.String())
	}
	if left, _ := os.ReadDir(cwd); len(left) != 0 {
		t.Errorf("the script left files in its working directory: %v", left)
	}
	return so.Bytes()
}

// untar unpacks a tar with the standard library and returns the file names, slash-separated, relative to dir.
func untar(t *testing.T, data []byte, dir string) []string {
	t.Helper()
	var names []string
	r := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := r.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		rel := filepath.Clean(h.Name)
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatal("the tar names a path outside its directory:", h.Name)
		}
		dst := filepath.Join(dir, rel)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				t.Fatal(err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, b, 0o644); err != nil {
				t.Fatal(err)
			}
			names = append(names, filepath.ToSlash(rel))
		default:
			t.Fatalf("%s: the tar holds a type %q: only files and directories are expected", h.Name, h.Typeflag)
		}
	}
}

// treeBytes is the size of the files under dir.
func treeBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err == nil {
			n += info.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// hostJSON is the report of host --offline on a tree, without the target's label (a path differs by design).
func hostJSON(t *testing.T, bin, cache, root string) (int, map[string]any) {
	t.Helper()
	r := runBinary(t, bin, cache, "host", "--offline", "--json", "--root", root)
	var v map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil {
		t.Fatalf("%v\n%s\n%s", err, r.stdout, r.stderr)
	}
	if target, ok := v["target"].(map[string]any); ok {
		delete(target, "value")
	}
	return r.code, v
}

func runBinary(t *testing.T, bin, cache string, args ...string) out {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "XDG_CACHE_HOME="+cache, "RASOAT_DATA_URL="+nowhere, "RASOAT_LINUX_DATA_URL="+nowhere, "LC_ALL=", "LC_MESSAGES=", "LANG=en_US.UTF-8")
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out{code, so.String(), se.String()}
}

func sameAnswer(t *testing.T, bin, cache, full, filtered string) {
	t.Helper()
	c1, a := hostJSON(t, bin, cache, full)
	c2, b := hostJSON(t, bin, cache, filtered)
	if c1 != c2 || !reflect.DeepEqual(a, b) {
		ja, _ := json.MarshalIndent(a, "", " ")
		jb, _ := json.MarshalIndent(b, "", " ")
		t.Errorf("the filtered tree gives another answer (exit %d, %d)\nfull:\n%s\nfiltered:\n%s", c1, c2, ja, jb)
	}
	if host, _ := a["host"].(map[string]any); host == nil || host["packages"] == nil || host["packages"].(float64) == 0 {
		t.Error("no packages were read: the comparison proves nothing")
	}
}

func TestHostFilesGivesTheSameAnswerInLess(t *testing.T) {
	needPullTools(t)
	bin := buildBinary(t)
	cache := offlineCache(t)
	base := filepath.Join("internal", "linux", "testdata")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	trees := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.Contains(e.Name(), "ubuntu") {
			continue
		}
		trees++
		t.Run(e.Name(), func(t *testing.T) {
			full := filepath.Join(base, e.Name())
			data := pull(t, full)
			got := t.TempDir()
			untar(t, data, got)
			fullBytes, gotBytes := treeBytes(t, full), treeBytes(t, got)
			t.Logf("%s: whole tree %d bytes, pulled files %d bytes, tar %d bytes", e.Name(), fullBytes, gotBytes, len(data))
			if gotBytes >= fullBytes {
				t.Errorf("the pull is not smaller: %d >= %d", gotBytes, fullBytes)
			}
			sameAnswer(t, bin, cache, full, got)
		})
	}
	if trees == 0 {
		t.Fatal("no Ubuntu tree in", base)
	}
}

// Every name below is data the script must carry as data: nothing in it may run, split or expand.
func TestHostFilesQuotesWhatItReads(t *testing.T) {
	needPullTools(t)
	root := t.TempDir()
	marker := filepath.Join(t.TempDir(), "RAN")
	evil := []string{"a$(touch " + marker + ")", "b`touch " + marker + "`", "c;touch " + marker, "d'e\"f", "g*", "h  i"}
	write(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	status, listed := "", ""
	for i, name := range evil {
		version := "1.0-" + string(rune('a'+i)) + "$HOME"
		status += "Package: " + name + "\nStatus: install ok installed\nVersion: " + version + "\n\n"
		listed += "Package: " + name + "\nVersion: " + version + "\nDescription: kept? no\n\n"
	}
	status += "Package: gone\nStatus: deinstall ok config-files\nVersion: 9\n\n"
	listed += "Package: gone\nVersion: 9\n\nPackage: other\nVersion: 1\n\n"
	write(t, root, "var/lib/dpkg/status", status)
	write(t, root, "var/lib/dpkg/status.d/odd name '$x'", "Package: distroless one\nStatus: install ok installed\nVersion: 2\n")
	write(t, root, "var/lib/dpkg/status.d/skipped.md5sums", "abc  file\n")
	for _, f := range []string{"ex ample;$(x)'s.com_ubuntu_dists_noble", "arch`y`.org_ubuntu_dists_noble-updates"} {
		write(t, root, "var/lib/apt/lists/"+f+"_InRelease", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nSuite: noble\nMD5Sum:\n deadbeef 1 big\nSHA256:\n cafe 1 big\n")
		write(t, root, "var/lib/apt/lists/"+f+"_main_binary-amd64_Packages", listed)
	}
	write(t, root, "var/lib/apt/lists/lock", "not a list")
	write(t, root, "var/lib/apt/lists/x_dists_y_main_binary-amd64_Packages.lz4", "compressed")

	data := pull(t, root)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a name in the tree ran as a command")
	}
	got := t.TempDir()
	names := untar(t, data, got)
	for _, want := range []string{
		"var/lib/dpkg/status.d/odd name '$x'",
		"var/lib/apt/lists/ex ample;$(x)'s.com_ubuntu_dists_noble_InRelease",
		"var/lib/apt/lists/arch`y`.org_ubuntu_dists_noble-updates_main_binary-amd64_Packages",
		"etc/os-release",
	} {
		if !contains(names, want) {
			t.Errorf("%q is not in the tar: %q", want, names)
		}
	}
	for _, not := range []string{"var/lib/dpkg/status.d/skipped.md5sums", "var/lib/apt/lists/lock", "var/lib/apt/lists/x_dists_y_main_binary-amd64_Packages.lz4"} {
		if contains(names, not) {
			t.Error(not, "is in the tar")
		}
	}
	header, err := os.ReadFile(filepath.Join(got, "var/lib/apt/lists/ex ample;$(x)'s.com_ubuntu_dists_noble_InRelease"))
	if err != nil || !strings.Contains(string(header), "Origin: Ubuntu") || strings.Contains(string(header), "deadbeef") {
		t.Errorf("a release file is cut to its header: %v %q", err, header)
	}
	list, err := os.ReadFile(filepath.Join(got, "var/lib/apt/lists/arch`y`.org_ubuntu_dists_noble-updates_main_binary-amd64_Packages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range evil {
		if !strings.Contains(string(list), "Package: "+name+"\n") {
			t.Errorf("the stanza of %q was dropped:\n%s", name, list)
		}
	}
	if strings.Contains(string(list), "other") || strings.Contains(string(list), "gone") || strings.Contains(string(list), "Description") {
		t.Errorf("only the installed Package and Version lines are kept:\n%s", list)
	}
	sameAnswer(t, buildBinary(t), offlineCache(t), root, got)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestHostFilesOnAnEmptyRootStillMakesATar(t *testing.T) {
	needPullTools(t)
	data := pull(t, t.TempDir())
	if names := untar(t, data, t.TempDir()); len(names) != 0 {
		t.Error(names)
	}
}
