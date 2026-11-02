package linux

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rasoat/rasoat/internal/data"
)

const (
	maxDownload = 256 << 20
	maxPlain    = 1 << 30
	staleDays   = 7
)

// BaseURL is where the files live. Fetching one says which distro release asks, and nothing about what it has installed.
func BaseURL() string {
	if u := os.Getenv("RASOAT_LINUX_DATA_URL"); u != "" {
		return strings.TrimRight(u, "/") + "/"
	}
	return "https://github.com/rasoat/rasoat/releases/download/linux-data/"
}

// Line is one release line of a product: when its support ends.
type Line struct {
	Cycle    string `json:"cycle"`
	EOL      string `json:"eol"`
	Latest   string `json:"latest"`
	Extended string `json:"extended"`
}

// Index says what is published and which release lines are alive.
type Index struct {
	Format int               `json:"format"`
	Built  string            `json:"built"`
	Files  map[string]int    `json:"files"`
	Lines  map[string][]Line `json:"lines"`
}

// Source says where a file came from. Origin: downloaded, cached, none. Problem: why a download attempted now was not used.
type Source struct {
	Built   string
	Origin  string
	Problem string
}

// fetchCached returns the file's bytes as cached, downloading at most once a day. check decides whether a download is good
// and is given the cached bytes, if any, to judge it against: a file older than the cache, or one that lost records, loses.
func fetchCached(name string, offline bool, userAgent string, parse func([]byte) (built string, records int, ok bool)) ([]byte, Source) {
	file := filepath.Join(data.CacheDir(), "linux", strings.TrimSuffix(name, ".gz"))
	var src Source
	cached, err := os.ReadFile(file)
	haveBuilt, haveRecords := "", 0
	if err == nil {
		if b, n, ok := parse(cached); ok {
			haveBuilt, haveRecords = b, n
			src = Source{Built: b, Origin: "cached"}
		} else {
			cached = nil
		}
	} else {
		cached = nil
	}
	if offline {
		return cached, src
	}
	if st, err := os.Stat(file); err == nil && cached != nil && time.Since(st.ModTime()) < 24*time.Hour {
		return cached, src
	}
	body, ok := data.Fetch(BaseURL()+name, userAgent, maxDownload)
	if !ok {
		src.Problem = "unreachable"
		return cached, src
	}
	if strings.HasSuffix(name, ".gz") {
		z, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			src.Problem = "invalid"
			return cached, src
		}
		plain, err := io.ReadAll(io.LimitReader(z, maxPlain))
		if err != nil {
			src.Problem = "invalid"
			return cached, src
		}
		body = plain
	}
	built, records, good := parse(body)
	switch {
	case !good:
		src.Problem = "invalid"
		return cached, src
	case cached != nil && built < haveBuilt:
		src.Problem = "older"
		return cached, src
	case cached != nil && float64(records) < float64(haveRecords)*0.9:
		src.Problem = "lost-records"
		return cached, src
	}
	data.WriteCache(file, body)
	return body, Source{Built: built, Origin: "downloaded"}
}

func parseIndex(b []byte) (string, int, bool) {
	var i Index
	if json.Unmarshal(b, &i) != nil || i.Format != 1 || i.Built == "" || i.Lines == nil {
		return "", 0, false
	}
	return i.Built, len(i.Files), true
}

// LoadIndex returns nil when there is none to be had.
func LoadIndex(offline bool, userAgent string) (*Index, Source) {
	b, src := fetchCached("index.json", offline, userAgent, parseIndex)
	if b == nil {
		return nil, src
	}
	var i Index
	if json.Unmarshal(b, &i) != nil {
		return nil, src
	}
	return &i, src
}

type fileHead struct {
	Format  int    `json:"format"`
	ID      string `json:"id"`
	Built   string `json:"built"`
	Records int    `json:"records"`
}

func parseHead(id string) func([]byte) (string, int, bool) {
	return func(b []byte) (string, int, bool) {
		end := bytes.IndexByte(b, '\n')
		if end < 0 {
			return "", 0, false
		}
		var h fileHead
		if json.Unmarshal(b[:end], &h) != nil || h.Format != 1 || h.ID != id || h.Built == "" {
			return "", 0, false
		}
		return h.Built, h.Records, true
	}
}

// LoadFile returns a data file's lines, header removed; nil when there is none to be had.
func LoadFile(id string, offline bool, userAgent string) ([]byte, Source) {
	b, src := fetchCached(id+".tsv.gz", offline, userAgent, parseHead(id))
	if b == nil {
		return nil, src
	}
	return b[bytes.IndexByte(b, '\n')+1:], src
}

// Fixed is one published fix for a package.
type Fixed struct {
	ID       string
	Version  string
	Severity string
}

// Advisories is a release's data for the packages asked about.
type Advisories struct {
	Fixed map[string][]Fixed
	Open  map[string]int
}

// PickAdvisories reads only the lines for wanted packages: a file can hold a million lines, a machine has a few hundred
// packages, and this runs on every scan.
func PickAdvisories(lines []byte, wanted map[string]bool) Advisories {
	out := Advisories{Fixed: map[string][]Fixed{}, Open: map[string]int{}}
	for len(lines) > 0 {
		end := bytes.IndexByte(lines, '\n')
		var line []byte
		if end < 0 {
			line, lines = lines, nil
		} else {
			line, lines = lines[:end], lines[end+1:]
		}
		tab := bytes.IndexByte(line, '\t')
		if tab <= 0 || !wanted[string(line[:tab])] {
			continue
		}
		f := strings.Split(string(line), "\t")
		if len(f) != 4 {
			continue
		}
		if f[1] == "" {
			n, _ := strconv.Atoi(f[3])
			out.Open[f[0]] = n
			continue
		}
		out.Fixed[f[0]] = append(out.Fixed[f[0]], Fixed{f[1], f[2], f[3]})
	}
	return out
}

// KernelCVE is one upstream kernel CVE.
type KernelCVE struct {
	ID         string
	Introduced string
	Unaffected []string // from:to, where to is an exact <bound, a line such as 5.15.*, or *
}

// ReadKernel parses the upstream file.
func ReadKernel(lines []byte) []KernelCVE {
	var out []KernelCVE
	sc := bufio.NewScanner(bytes.NewReader(lines))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 3 {
			continue
		}
		c := KernelCVE{ID: f[0], Introduced: f[1]}
		if f[2] != "" {
			c.Unaffected = strings.Split(f[2], ",")
		}
		out = append(out, c)
	}
	return out
}
