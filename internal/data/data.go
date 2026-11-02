// Package data decides which snapshot a scan answers from: the newest good one of a daily download, the cached download,
// and the copy the binary was built with. The download is one plain GET; it carries nothing about what is being scanned.
package data

import (
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/roots"
)

//go:embed snapshot.json
var bundledBytes []byte

// bundledMeta is what choosing between snapshots needs. Parsing the built-in megabyte is most of a run's time, and a run
// with a good cache never has to.
//
//go:embed snapshot.meta.json
var bundledMeta []byte

type meta struct {
	Built  string `json:"built"`
	Counts []int  `json:"counts"`
}

const (
	dayMs     = 24 * time.Hour
	staleDays = 7
	maxBytes  = 32 << 20
)

// Bundled is the copy from this binary's build.
var Bundled = sync.OnceValue(func() *core.Snapshot {
	s := core.ParseSnapshot(bundledBytes)
	if s == nil {
		panic("the built-in data is malformed")
	}
	return s
})

// Loaded is a snapshot and how it was chosen. Origin: downloaded, cached, bundled. Problem: why a download attempted now
// was not used: unreachable, invalid, older, lost-records.
type Loaded struct {
	Snapshot *core.Snapshot
	Origin   string
	AgeDays  int
	Stale    bool
	Problem  *string
}

// CacheDir is where downloads are kept.
func CacheDir() string {
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "rasoat")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "rasoat")
	}
	return filepath.Join(home, ".cache", "rasoat")
}

func dataURL() string {
	if u := os.Getenv("RASOAT_DATA_URL"); u != "" {
		return u
	}
	return "https://rasoat.com/data/snapshot-v1.json"
}

// Fetch is one GET with a size limit; the error says only that it did not work.
func Fetch(url, userAgent string, limit int64) ([]byte, bool) {
	roots.Ensure()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, false
	}
	return body, true
}

// WriteCache renames into place: a crash leaves the old cache, never half a file. A read-only home costs a re-download.
func WriteCache(file string, body []byte) {
	if os.MkdirAll(filepath.Dir(file), 0o755) != nil {
		return
	}
	tmp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if os.WriteFile(tmp, body, 0o644) != nil {
		return
	}
	if os.Rename(tmp, file) != nil {
		os.Remove(tmp)
	}
}

func loaded(s *core.Snapshot, origin, problem string) *Loaded {
	built, _ := time.Parse("2006-01-02", s.Built)
	age := max(0, int(time.Since(built)/dayMs))
	l := &Loaded{Snapshot: s, Origin: origin, AgeDays: age, Stale: age > staleDays}
	if problem != "" {
		l.Problem = &problem
	}
	return l
}

// Load chooses the snapshot. Never go back: a cache older than the binary's own copy, or one that lost records against
// it, loses to the copy.
func Load(offline bool, userAgent string) *Loaded {
	var floor meta
	if err := json.Unmarshal(bundledMeta, &floor); err != nil {
		panic(err)
	}
	file := filepath.Join(CacheDir(), "snapshot-v1.json")
	var best *core.Snapshot
	origin := "bundled"
	fresh := false
	if b, err := os.ReadFile(file); err == nil {
		if s := core.ParseSnapshot(b); s != nil && s.Built >= floor.Built && core.KeepsCoverage(s.Counts(), floor.Counts) {
			best, origin = s, "cached"
			if st, err := os.Stat(file); err == nil {
				fresh = time.Since(st.ModTime()) < dayMs
			}
		}
	}
	current := func() *core.Snapshot {
		if best != nil {
			return best
		}
		return Bundled()
	}
	if offline || fresh {
		return loaded(current(), origin, "")
	}
	body, ok := Fetch(dataURL(), userAgent, maxBytes)
	if !ok {
		return loaded(current(), origin, "unreachable")
	}
	got := core.ParseSnapshot(body)
	if got == nil {
		return loaded(current(), origin, "invalid")
	}
	builtNow, countsNow := floor.Built, floor.Counts
	if best != nil {
		builtNow, countsNow = best.Built, best.Counts()
	}
	switch {
	case got.Built < builtNow:
		return loaded(current(), origin, "older")
	case !core.KeepsCoverage(got.Counts(), countsNow):
		return loaded(current(), origin, "lost-records")
	}
	WriteCache(file, body)
	return loaded(got, "downloaded", "")
}
