package main

// The speed and memory budget, judged on the built program: a tag cannot ship if reading a machine got slow or heavy.
// BUDGET_SCALE multiplies every limit (a float, default 1) for slow or emulated runners.
import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	hostBudget    = 2 * time.Second
	hostRSSBudget = 64 << 20
	scanBudget    = 3 * time.Second
	budgetRuns    = 3 // the best of three: a busy runner makes one run slow, never all
)

func budgetScale(t *testing.T) float64 {
	t.Helper()
	s := os.Getenv("BUDGET_SCALE")
	if s == "" {
		return 1
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		t.Fatalf("BUDGET_SCALE=%q: want a positive number", s)
	}
	return f
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "rasoat")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return bin
}

// dirFiles counts the files under dir: many small files cost a walk more than one large one.
func dirFiles(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// largest is the subdirectory with most files of parent whose name has the substring.
func largest(t *testing.T, parent, contains string) string {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	best, bestSize := "", int64(-1)
	for _, e := range entries {
		if !e.IsDir() || !strings.Contains(e.Name(), contains) {
			continue
		}
		if n := dirFiles(t, filepath.Join(parent, e.Name())); n > bestSize {
			best, bestSize = filepath.Join(parent, e.Name()), n
		}
	}
	if best == "" {
		t.Fatal("no directory with", contains, "in", parent)
	}
	return best
}

// offlineCache is the data cache a host run reads without any network: real file shapes, a release line, two advisories.
func offlineCache(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	write(t, cache, "rasoat/linux/index.json", `{"format":1,"built":"2099-01-01","files":{"ubuntu-24.04":1},"lines":{"ubuntu":[{"cycle":"24.04","eol":"2099-05-31"}],"linux":[]}}`)
	write(t, cache, "rasoat/linux/ubuntu-24.04.tsv", `{"format":1,"id":"ubuntu-24.04","built":"2099-01-01","records":2}`+"\nopenssl\tUSN-1\t3.0.13-0ubuntu3.99\thigh\napt\tUSN-2\t9:2.7.14build2\tmedium\n")
	return cache
}

// timed runs the program budgetRuns times and returns the best time and the best peak memory. ok false: no rusage here.
func timed(t *testing.T, bin, cache string, args ...string) (best time.Duration, rss int64, ok bool, stdout string) {
	t.Helper()
	best, rss = time.Duration(1<<62), 1<<62
	for range budgetRuns {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "XDG_CACHE_HOME="+cache, "RASOAT_DATA_URL="+nowhere, "RASOAT_LINUX_DATA_URL="+nowhere, "LC_ALL=", "LC_MESSAGES=", "LANG=en_US.UTF-8")
		start := time.Now()
		b, err := cmd.Output() // a verdict exit code (1, 3) is an answer, not a failure
		d := time.Since(start)
		if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
			t.Fatal(err)
		}
		stdout = string(b)
		best = min(best, d)
		if m, has := maxRSS(cmd); has {
			rss, ok = min(rss, m), true
		}
	}
	return best, rss, ok, stdout
}

func TestBudgetHostOnTheLargestUbuntuTree(t *testing.T) {
	scale := budgetScale(t)
	bin := buildBinary(t)
	tree := largest(t, filepath.Join("internal", "linux", "testdata"), "ubuntu")
	d, rss, ok, stdout := timed(t, bin, offlineCache(t), "host", "--offline", "--json", "--root", tree)
	var rep rep_
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	// A fast run that judged nothing proves nothing.
	if rep.Host.Packages == 0 || strings.Contains(stdout, "package-data-not-available") {
		t.Fatalf("the run did not judge packages offline: %d read\n%s", rep.Host.Packages, stdout)
	}
	t.Logf("host --offline on %s (%d packages): best %v of %d, peak %.1f MB", filepath.ToSlash(tree), rep.Host.Packages, d.Round(time.Millisecond), budgetRuns, float64(rss)/(1<<20))
	if limit := time.Duration(float64(hostBudget) * scale); d > limit {
		t.Errorf("host took %v, budget %v", d, limit)
	}
	if ok {
		if limit := int64(float64(hostRSSBudget) * scale); rss > limit {
			t.Errorf("host peak memory %d bytes, budget %d", rss, limit)
		}
	}
}

func TestBudgetScanOnTheLargestFixture(t *testing.T) {
	scale := budgetScale(t)
	bin := buildBinary(t)
	repo := largest(t, "fixtures", "")
	d, rss, _, _ := timed(t, bin, t.TempDir(), "scan", repo, "--offline", "--json")
	t.Logf("scan --offline on %s: best %v of %d, peak %.1f MB", filepath.ToSlash(repo), d.Round(time.Millisecond), budgetRuns, float64(rss)/(1<<20))
	if limit := time.Duration(float64(scanBudget) * scale); d > limit {
		t.Errorf("scan took %v, budget %v", d, limit)
	}
}
