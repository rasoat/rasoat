// linux-data builds the Linux advisory files `rasoat host` downloads: one small file per distro release, one for the
// upstream kernel, one index. From public sources only, with no advisory prose: package, id, fixed version, severity.
//
// Usage: go run ./cmd/linux-data --work DIR --out DIR [--only Debian,Alpine] [--kernel-vulns DIR]
package main

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const osvBase = "https://osv-vulnerabilities.storage.googleapis.com/"

// Each OSV ecosystem export, and how its ecosystem names map to one file per release.
var sources = []struct {
	export string
	file   func(eco string) string
}{
	{"Debian", match(`^Debian:(\d+)$`, "debian-$1", func(m []string) bool { return len(m[1]) <= 2 && atoi(m[1]) >= 9 })},
	{"Ubuntu", match(`^Ubuntu:(\d+\.\d+)(?::LTS)?$`, "ubuntu-$1", nil)},
	{"AlmaLinux", match(`^AlmaLinux:(\d+)$`, "almalinux-$1", nil)},
	{"Rocky Linux", match(`^Rocky Linux:(\d+)$`, "rocky-$1", nil)},
	{"Red Hat", match(`^Red Hat:enterprise_linux:(\d+)(?:\.\d+)?(?:::(?:baseos|appstream|crb|server|workstation|client|computenode|highavailability|resilientstorage|nfv|realtime|sap\w*))?$`, "rhel-$1", func(m []string) bool { return atoi(m[1]) >= 7 })},
	{"Alpine", match(`^Alpine:v(\d+\.\d+)$`, "alpine-$1", nil)},
	{"openSUSE", openSUSE},
	{"SUSE", openSUSE},
}

func atoi(s string) int {
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}

func match(pattern, tmpl string, keep func([]string) bool) func(string) string {
	re := regexp.MustCompile(pattern)
	return func(eco string) string {
		m := re.FindStringSubmatch(eco)
		if m == nil || (keep != nil && !keep(m)) {
			return ""
		}
		return re.ReplaceAllString(eco, tmpl)
	}
}

var (
	leap = regexp.MustCompile(`^openSUSE:Leap (\d+\.\d+)$`)
	sle  = regexp.MustCompile(`^SUSE:Linux Enterprise (?:Server(?: for SAP Applications)?|High Performance Computing|Module for [A-Za-z0-9 ]+) (\d+)(?: SP(\d+)|\.(\d+))?(?:-LTSS|-ESPOS)?$`)
)

func openSUSE(eco string) string {
	if m := leap.FindStringSubmatch(eco); m != nil {
		return "opensuse-leap-" + m[1]
	}
	if eco == "openSUSE:Tumbleweed" {
		return "opensuse-tumbleweed"
	}
	if m := sle.FindStringSubmatch(eco); m != nil {
		minor := "0"
		if m[2] != "" {
			minor = m[2]
		} else if m[3] != "" {
			minor = m[3]
		}
		return "sles-" + m[1] + "." + minor
	}
	return ""
}

type record struct {
	ID        string   `json:"id"`
	Withdrawn string   `json:"withdrawn"`
	Summary   string   `json:"summary"`
	Upstream  []string `json:"upstream"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Urgency string `json:"urgency"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

type entry struct {
	id, fixed, severity string
	cves                []string
}

type release struct {
	pkgs map[string][]entry
	open map[string]map[string]bool // package to the CVEs with no fix published yet
}

var rhSeverity = regexp.MustCompile(`(?i)^(critical|important|moderate|low)\b`)

// cvss31Base computes a CVSS v3 base score from its vector.
func cvss31Base(vector string) float64 {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	w := func(table map[string]float64, key string) float64 { return table[m[key]] }
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	impactTable := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	isc := 1 - (1-w(impactTable, "C"))*(1-w(impactTable, "I"))*(1-w(impactTable, "A"))
	impact := 6.42 * isc
	if changed {
		impact = 7.52*(isc-0.029) - 3.25*math.Pow(isc-0.02, 15)
	}
	exploit := 8.22 * w(map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AV") * w(map[string]float64{"L": 0.77, "H": 0.44}, "AC") * w(pr, "PR") * w(map[string]float64{"N": 0.85, "R": 0.62}, "UI")
	if impact <= 0 {
		return 0
	}
	score := impact + exploit
	if changed {
		score *= 1.08
	}
	return math.Ceil(math.Min(score, 10)*10) / 10
}

func severityOf(r *record, urgency string) string {
	if m := rhSeverity.FindStringSubmatch(r.Summary); m != nil {
		switch strings.ToLower(m[1]) {
		case "critical":
			return "critical"
		case "important":
			return "high"
		case "moderate":
			return "medium"
		case "low":
			return "low"
		}
	}
	for _, s := range r.Severity { // a distro's own word wins over a score
		if s.Type == "Ubuntu" {
			switch s.Score {
			case "critical", "high", "medium", "low":
				return s.Score
			case "negligible":
				return "low"
			}
		}
	}
	switch urgency {
	case "high", "medium", "low":
		return urgency
	case "unimportant":
		return "low"
	}
	best := 0.0
	for _, s := range r.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			best = math.Max(best, cvss31Base(s.Score))
		}
	}
	switch {
	case best >= 9:
		return "critical"
	case best >= 7:
		return "high"
	case best >= 4:
		return "medium"
	case best > 0:
		return "low"
	}
	return "unknown"
}

func collect(z *zip.Reader, file func(string) string, out map[string]*release) error {
	for _, f := range z.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		var r record
		err = json.NewDecoder(rc).Decode(&r)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if r.Withdrawn != "" {
			continue
		}
		cves := r.Upstream
		if len(cves) == 0 {
			cves = []string{r.ID}
		}
		for _, a := range r.Affected {
			slug := file(a.Package.Ecosystem)
			if slug == "" || a.Package.Name == "" {
				continue
			}
			rel := out[slug]
			if rel == nil {
				rel = &release{pkgs: map[string][]entry{}, open: map[string]map[string]bool{}}
				out[slug] = rel
			}
			fixed := ""
			for _, g := range a.Ranges {
				if g.Type != "ECOSYSTEM" {
					continue
				}
				for _, ev := range g.Events {
					if ev.Fixed != "" {
						fixed = ev.Fixed
					}
				}
			}
			if fixed == "" {
				if rel.open[a.Package.Name] == nil {
					rel.open[a.Package.Name] = map[string]bool{}
				}
				for _, c := range cves {
					rel.open[a.Package.Name][c] = true
				}
				continue
			}
			rel.pkgs[a.Package.Name] = append(rel.pkgs[a.Package.Name], entry{r.ID, fixed, severityOf(&r, a.EcosystemSpecific.Urgency), cves})
		}
	}
	return nil
}

// reduce drops an advisory whose every CVE another advisory for this package already states at the same fixed version: a
// distro publishes both a per-CVE record and a notice that names several, and listing both would count one hole twice. A
// later fix for the same CVE stays: it can be the one that really closes it.
func reduce(entries []entry) []entry {
	sort.SliceStable(entries, func(i, j int) bool {
		if len(entries[i].cves) != len(entries[j].cves) {
			return len(entries[i].cves) < len(entries[j].cves)
		}
		return entries[i].id < entries[j].id
	})
	seen := map[string]bool{}
	var out []entry
	for _, e := range entries {
		fresh := false
		for _, c := range e.cves {
			if key := c + " " + e.fixed; !seen[key] {
				fresh = true
				seen[key] = true
			}
		}
		if fresh {
			out = append(out, e)
		}
	}
	return out
}

// sourceOf is where a file's data comes from and its terms, carried in the file. These files are adapted data, published
// under the same terms; the program is not built from them and keeps its own licence.
func sourceOf(id string) (source, license string) {
	switch {
	case strings.HasPrefix(id, "ubuntu-"):
		return "Canonical, ubuntu-security-notices, through OSV.dev", "CC-BY-SA-4.0"
	case strings.HasPrefix(id, "alpine-"):
		return "Alpine SecDB, through OSV.dev", "CC-BY-SA-4.0"
	case strings.HasPrefix(id, "rhel-"):
		return "Red Hat Security Data, through OSV.dev", "CC-BY-4.0"
	case strings.HasPrefix(id, "almalinux-"):
		return "AlmaLinux errata, through OSV.dev", "MIT"
	case strings.HasPrefix(id, "rocky-"):
		return "Rocky Linux errata, through OSV.dev", "BSD"
	case strings.HasPrefix(id, "debian-"):
		return "Debian Security Tracker, through OSV.dev", "as published by Debian"
	case strings.HasPrefix(id, "sles-"), strings.HasPrefix(id, "opensuse-"):
		return "SUSE security data, through OSV.dev", "as published by SUSE"
	}
	return "kernel.org CVE records (vulns.git)", "CVE-ToU"
}

func clean(s string) string { return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s) }

// A release file: one JSON header line, then package<TAB>id<TAB>fixed<TAB>severity, or package<TAB><TAB><TAB>open-count.
// Tab-separated so a scan can read only the packages installed, where a JSON document would be parsed whole.
func writeRelease(path, id, built string, rel *release) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	z, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	w := bufio.NewWriter(z)
	names := make([]string, 0, len(rel.pkgs))
	count := 0
	for n, e := range rel.pkgs {
		rel.pkgs[n] = reduce(e)
		count += len(rel.pkgs[n])
		names = append(names, n)
	}
	for n := range rel.open {
		if _, ok := rel.pkgs[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	source, license := sourceOf(id)
	head, _ := json.Marshal(map[string]any{"format": 1, "id": id, "built": built, "records": count, "source": source, "license": license})
	w.Write(head)
	w.WriteByte('\n')
	for _, n := range names {
		for _, e := range rel.pkgs[n] {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", clean(n), clean(e.id), clean(e.fixed), e.severity)
		}
		if c := len(rel.open[n]); c > 0 {
			fmt.Fprintf(w, "%s\t\t\t%d\n", clean(n), c)
		}
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	return count, z.Close()
}

func download(rawURL, file string) error {
	if st, err := os.Stat(file); err == nil && time.Since(st.ModTime()) < 12*time.Hour && st.Size() > 0 {
		return nil
	}
	resp, err := http.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	tmp := file + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, file)
}

// kernelCNA is the shape of a kernel.org CVE record, as far as this needs it.
type kernelCNA struct {
	CveMetadata struct {
		CveID string `json:"cveId"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Affected []struct {
				DefaultStatus string `json:"defaultStatus"`
				Versions      []struct {
					Version         string `json:"version"`
					LessThan        string `json:"lessThan"`
					LessThanOrEqual string `json:"lessThanOrEqual"`
					Status          string `json:"status"`
					VersionType     string `json:"versionType"`
				} `json:"versions"`
			} `json:"affected"`
		} `json:"cna"`
	} `json:"containers"`
}

// kernel writes one line per CVE: id<TAB>introduced<TAB>from:to,from:to. A version is affected if it is at or above
// introduced and in no from:to range. `to` is an exact bound, a line such as 5.15.*, or * for everything above.
func kernel(dir, path, built string) (int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "cve", "published", "*", "CVE-*.json"))
	if err != nil {
		return 0, err
	}
	sort.Strings(files)
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	z, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	w := bufio.NewWriter(z)
	var lines []string
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return 0, err
		}
		var r kernelCNA
		if err := json.Unmarshal(b, &r); err != nil {
			return 0, fmt.Errorf("%s: %w", file, err)
		}
		for _, a := range r.Containers.CNA.Affected {
			if a.DefaultStatus != "affected" {
				continue
			}
			intro := ""
			var ranges []string
			for _, v := range a.Versions {
				switch {
				case v.Status == "affected" && v.VersionType != "git":
					intro = v.Version
				case v.Status == "unaffected" && v.Version == "0":
					// below the version that introduced it: covered by intro
				case v.Status == "unaffected" && v.LessThanOrEqual != "":
					ranges = append(ranges, v.Version+":"+v.LessThanOrEqual)
				case v.Status == "unaffected" && v.LessThan != "":
					ranges = append(ranges, v.Version+":<"+v.LessThan)
				}
			}
			if intro != "" {
				lines = append(lines, r.CveMetadata.CveID+"\t"+intro+"\t"+strings.Join(ranges, ","))
			}
		}
	}
	source, license := sourceOf("linux-kernel")
	head, _ := json.Marshal(map[string]any{"format": 1, "id": "linux-kernel", "built": built, "records": len(lines), "source": source, "license": license})
	w.Write(head)
	w.WriteByte('\n')
	for _, l := range lines {
		w.WriteString(l + "\n")
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	return len(lines), z.Close()
}

type eolCycle struct {
	Cycle           string `json:"cycle"`
	EOL             any    `json:"eol"`
	Latest          any    `json:"latest"`
	ExtendedSupport any    `json:"extendedSupport"`
}

type line struct {
	Cycle    string `json:"cycle"`
	EOL      string `json:"eol,omitempty"`
	Latest   string `json:"latest,omitempty"`
	Extended string `json:"extended,omitempty"`
}

func dateOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func endOfLife(product string) ([]line, error) {
	resp, err := http.Get("https://endoflife.date/api/" + url.PathEscape(product) + ".json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("endoflife %s: %s", product, resp.Status)
	}
	var cycles []eolCycle
	if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
		return nil, err
	}
	out := []line{}
	for _, c := range cycles {
		l := line{Cycle: c.Cycle, EOL: dateOf(c.EOL), Latest: dateOf(c.Latest), Extended: dateOf(c.ExtendedSupport)}
		// A true eol with no date: past it, date unknown.
		if b, ok := c.EOL.(bool); ok && b {
			l.EOL = "1970-01-01"
		}
		out = append(out, l)
	}
	return out, nil
}

func main() {
	work := flag.String("work", "", "directory for downloads")
	out := flag.String("out", "", "directory for the files")
	only := flag.String("only", "", "comma-separated OSV exports; default all")
	vulns := flag.String("kernel-vulns", "", "a checkout of kernel.org's vulns.git; empty leaves the kernel file out")
	flag.Parse()
	if *work == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*work, *out, *only, *vulns); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(work, out, only, vulns string) error {
	for _, d := range []string{work, out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	built := time.Now().UTC().Format("2006-01-02")
	releases := map[string]*release{}
	for _, s := range sources {
		if only != "" && !slices.Contains(strings.Split(only, ","), s.export) {
			continue
		}
		file := filepath.Join(work, strings.ReplaceAll(s.export, " ", "_")+".zip")
		if err := download(osvBase+url.PathEscape(s.export)+"/all.zip", file); err != nil {
			return err
		}
		z, err := zip.OpenReader(file)
		if err != nil {
			return err
		}
		err = collect(&z.Reader, s.file, releases)
		z.Close()
		if err != nil {
			return err
		}
		fmt.Printf("%s read, %d releases so far\n", s.export, len(releases))
	}
	files := map[string]int{}
	for id, rel := range releases {
		n, err := writeRelease(filepath.Join(out, id+".tsv.gz"), id, built, rel)
		if err != nil {
			return err
		}
		files[id] = n
	}
	if vulns != "" {
		n, err := kernel(vulns, filepath.Join(out, "linux-kernel.tsv.gz"), built)
		if err != nil {
			return err
		}
		files["linux-kernel"] = n
	}
	lines := map[string][]line{}
	for _, p := range []string{"ubuntu", "debian", "rhel", "almalinux", "rocky-linux", "centos", "fedora", "amazon-linux", "oracle-linux", "alpine-linux", "opensuse", "sles", "linux"} {
		l, err := endOfLife(p)
		if err != nil {
			return err
		}
		lines[p] = l
	}
	index, err := json.MarshalIndent(map[string]any{"format": 1, "built": built, "files": files, "lines": lines}, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "index.json"), index, 0o644); err != nil {
		return err
	}
	ids := make([]string, 0, len(files))
	for id := range files {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		name := id + ".tsv.gz"
		st, err := os.Stat(filepath.Join(out, name))
		if err != nil {
			return err
		}
		fmt.Printf("%-24s %7d records %8d KB\n", id, files[id], st.Size()/1000)
	}
	return nil
}
