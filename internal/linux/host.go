package linux

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rasoat/rasoat/internal/core"
)

// Options says what to judge. Root "/" and no Kernel: the machine this runs on.
type Options struct {
	Root      string
	Kernel    string // judge this kernel version instead of the running one
	Offline   bool
	UserAgent string
	Today     string
}

// Finding is the result for one thing on the host: the release, the kernel, or a source package.
type Finding struct {
	core.Verdict
	Installed []string // binary packages behind a source package
	How       string
}

// Host is everything a scan of a machine found.
type Host struct {
	Distro      *Distro
	Family      string
	Packages    int // installed packages read
	OK          int // source packages judged, with nothing found
	Open        int // published CVEs reaching installed packages with no fix yet: a count, not a finding
	Running     string
	Newest      string // newest kernel package installed, as uname -r would say it
	Reboot      bool
	InContainer bool
	Findings    []Finding
	Notes       []string
	Index       Source
	Data        Source
	UpgradeCmd  string
}

// Notices are what the Linux data asks to be shown.
var Notices = []string{"Linux advisories, through OSV.dev: Ubuntu and Alpine (CC-BY-SA-4.0), Red Hat (CC-BY-4.0), AlmaLinux (MIT), Rocky Linux (BSD), Debian and SUSE (no licence published at the source). Upstream kernel: kernel.org (CVE-ToU). Release lines: endoflife.date. Each data file names its source, terms and links; NOTICE.txt in the data release repeats them. Not affiliated with any of them. Linux is a registered trademark of Linus Torvalds."}

// ErrNotLinux: no os-release under this root.
var ErrNotLinux = errors.New("no /etc/os-release under this root: not a Linux root")

func readRunningKernel(root string) string {
	b, err := readFile(root, "proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// inContainer: the kernel a process sees then is the host's, and no package here says anything about it.
func inContainer(root string) bool {
	for _, p := range []string{".dockerenv", "run/.containerenv"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	b, err := readFile(root, "proc/1/cgroup")
	return err == nil && regexp.MustCompile(`docker|containerd|kubepods|lxc|podman`).Match(b)
}

func distroVerdict(d *Distro, index *Index, today string) (verdict core.Verdict, extended string) {
	version := d.Version
	if version == "" {
		version = "rolling"
	}
	reason := func(r string) (core.Verdict, string) {
		return core.Verdict{Product: d.ID, Version: &version, Status: core.Unknown, Reason: &r, Advisories: []core.VerdictAdvisory{}}, ""
	}
	if index == nil || d.Cycle == "" {
		return reason("line-not-listed")
	}
	lines := index.Lines[d.Cycle]
	for _, l := range lines {
		if l.Cycle != d.Line && !strings.HasPrefix(l.Cycle, d.Line+" ") {
			continue
		}
		v := core.Verdict{Product: d.ID, Version: &version, Status: core.OK, Advisories: []core.VerdictAdvisory{}}
		if l.EOL != "" && l.EOL <= today {
			v.Status = core.Unsupported
			if l.Extended > today {
				extended = l.Extended
			}
			for _, n := range lines { // lines are newest first: the newest supported one
				if n.EOL == "" || n.EOL > today {
					fix := n.Cycle
					v.Fix = &fix
					break
				}
			}
			if v.Fix == nil {
				v.NoFix = true
			}
		}
		return v, extended
	}
	return reason("line-not-listed")
}

// moduleOK: an rpm advisory speaks for its own build stream. One for php:8.2 says nothing about php:8.1, one for a modular
// build nothing about a plain package, and one for Rocky's Cloud SIG kernel (...el9_8.cloud.1.0) nothing about the standard
// kernel, whose version would always compare below it.
func moduleOK(p Package, fixed string) bool {
	for _, stream := range []string{".module", ".cloud."} {
		if strings.Contains(p.Version, stream) != strings.Contains(fixed, stream) {
			return false
		}
	}
	if p.Stream == "" || !isDigit(p.Stream[0]) {
		return true
	}
	_, v := splitEpoch(fixed)
	return strings.HasPrefix(v, p.Stream+".") || strings.HasPrefix(v, p.Stream+"-")
}

type group struct {
	source  string
	version string
	bins    []Package
}

func severityRankOf(a []core.VerdictAdvisory) int {
	best := 5
	for _, x := range a {
		best = min(best, core.SeverityRank(x.Severity))
	}
	return best
}

func advisoryOf(f Fixed) core.VerdictAdvisory {
	return core.VerdictAdvisory{ID: f.ID, Severity: f.Severity, URL: "https://osv.dev/vulnerability/" + f.ID}
}

// judge compares one installed version with a package's published fixes. The fix to move to is the highest it lacks.
func judge(family string, p Package, version string, fixes []Fixed) ([]core.VerdictAdvisory, string) {
	out := []core.VerdictAdvisory{}
	best := ""
	seen := map[string]bool{}
	for _, f := range fixes {
		if seen[f.ID] || (family == "rpm" && !moduleOK(p, f.Version)) {
			continue
		}
		seen[f.ID] = true
		if Compare(family, version, f.Version) < 0 {
			out = append(out, advisoryOf(f))
			if best == "" || Compare(family, f.Version, best) > 0 {
				best = f.Version
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := core.SeverityRank(out[i].Severity), core.SeverityRank(out[j].Severity); ri != rj {
			return ri < rj
		}
		return out[i].ID > out[j].ID
	})
	return out, best
}

// Safe for a command an agent may run: package names come from a file on the machine being read.
var safePackage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:-]*$`)

func upgradeCommand(family string, names []string) string {
	ok := names[:0:0]
	for _, n := range names {
		if safePackage.MatchString(n) {
			ok = append(ok, n)
		}
	}
	if len(ok) == 0 {
		return ""
	}
	sort.Strings(ok)
	list := strings.Join(ok, " ")
	switch family {
	case "deb":
		return "apt-get update && apt-get install --only-upgrade " + list
	case "rpm":
		return "dnf upgrade --refresh " + list
	case "apk":
		return "apk upgrade --update-cache " + list
	}
	return ""
}

// Scan judges a machine or a mounted root.
func Scan(o Options) (*Host, error) {
	if o.Today == "" {
		o.Today = time.Now().UTC().Format("2006-01-02")
	}
	d := DetectDistro(o.Root)
	if d == nil {
		return nil, ErrNotLinux
	}
	h := &Host{Distro: d, Family: d.Family, Findings: []Finding{}, Notes: []string{}, InContainer: inContainer(o.Root)}
	index, src := LoadIndex(o.Offline, o.UserAgent)
	h.Index = src
	release, extended := distroVerdict(d, index, o.Today)
	h.Findings = append(h.Findings, Finding{Verdict: release, How: "/etc/os-release"})
	if extended != "" {
		h.Notes = append(h.Notes, "paid-extended-support-until:"+extended)
	}

	// Packages that could not be judged are a row of their own: "nothing found" must not read as "nothing to find".
	unjudged := ""
	var pkgs []Package
	if d.Family == "" {
		unjudged = "package-database-not-read"
	} else {
		var err error
		pkgs, err = ReadPackages(o.Root, d.Family)
		switch {
		case errors.Is(err, os.ErrNotExist):
			unjudged = "package-database-not-found"
		case err != nil:
			unjudged = "package-database-unreadable"
		}
	}
	h.Packages = len(pkgs)

	groups := map[string]*group{}
	var images []Package
	for _, p := range pkgs {
		if isKernelBinary(d.Family, p.Name) {
			if isImage, _ := kernelImage(d.Family, p); isImage {
				images = append(images, p)
			}
			continue
		}
		key := p.Source + " " + p.SourceVersion
		g := groups[key]
		if g == nil {
			g = &group{source: p.Source, version: p.SourceVersion}
			groups[key] = g
		}
		g.bins = append(g.bins, p)
	}

	wanted := map[string]bool{}
	for _, g := range groups {
		wanted[g.source] = true
		for _, b := range g.bins {
			wanted[b.Name] = true
		}
	}
	running := o.Kernel
	if running == "" && o.Root == "/" && !h.InContainer {
		running = readRunningKernel(o.Root)
	}
	h.Running = running
	image, newest := chooseKernel(d.Family, images, running)
	h.Newest = newest
	h.Reboot = o.Kernel == "" && running != "" && image != nil && newest != "" && !kernelMatches(d.Family, *image, newest)
	var kernelFixName, kernelVersion string
	if image != nil {
		kernelFixName, kernelVersion = kernelSource(d.Family, *image)
		wanted[kernelFixName] = true
		wanted[image.Name] = true
	}

	var adv Advisories
	haveData := false
	if d.File != "" && d.Family != "" {
		lines, s := LoadFile(d.File, o.Offline, o.UserAgent)
		h.Data = s
		if lines != nil {
			haveData = true
			adv = PickAdvisories(lines, wanted)
		}
	}
	switch {
	case unjudged != "":
	case d.File == "":
		unjudged = "no-package-data-for-this-distro"
	case !haveData:
		unjudged = "package-data-not-available"
	}
	if unjudged != "" {
		count := strconv.Itoa(len(pkgs))
		h.Findings = append(h.Findings, Finding{Verdict: core.Verdict{Product: "packages", Version: &count, Status: core.Unknown, Reason: &unjudged, Advisories: []core.VerdictAdvisory{}}})
	}

	var upgrade []string
	if haveData {
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		openSeen := map[string]bool{}
		for _, k := range keys {
			g := groups[k]
			if !openSeen[g.source] {
				openSeen[g.source] = true
				h.Open += adv.Open[g.source]
			}
			// A source package's advisories, compared at its own version; on rpm, also advisories naming a binary directly.
			advs, fix := judge(d.Family, g.bins[0], g.version, adv.Fixed[g.source])
			if d.Family == "rpm" {
				seen := map[string]bool{}
				for _, a := range advs {
					seen[a.ID] = true
				}
				for _, b := range g.bins {
					if b.Name == g.source {
						continue
					}
					more, moreFix := judge(d.Family, b, b.Version, adv.Fixed[b.Name])
					for _, a := range more {
						if !seen[a.ID] {
							seen[a.ID] = true
							advs = append(advs, a)
						}
					}
					if moreFix != "" && (fix == "" || Compare(d.Family, moreFix, fix) > 0) {
						fix = moreFix
					}
				}
			}
			if len(advs) == 0 {
				h.OK++
				continue
			}
			version, fixp := g.version, fix
			f := Finding{Verdict: core.Verdict{Product: "pkg:" + g.source, Version: &version, Status: core.Vulnerable, Fix: &fixp, Advisories: advs}}
			for _, b := range g.bins {
				f.Installed = append(f.Installed, b.Name)
				upgrade = append(upgrade, b.Name)
			}
			h.Findings = append(h.Findings, f)
		}
	}
	h.UpgradeCmd = upgradeCommand(d.Family, upgrade)

	// The kernel is last: a distro's own package data, if a package explains it; then the number, for a plain kernel.
	switch {
	case o.Kernel == "" && h.InContainer:
		h.Notes = append(h.Notes, "kernel-belongs-to-the-container-host")
	case image != nil && haveData:
		advs, fix := judge(d.Family, *image, kernelVersion, adv.Fixed[kernelFixName])
		h.Open += adv.Open[kernelFixName]
		display := running
		if display == "" {
			display = newest
		}
		v := core.Verdict{Product: "linux", Version: &display, Status: core.OK, Advisories: advs}
		if len(advs) > 0 {
			v.Status = core.Vulnerable
			v.Fix = &fix
		}
		h.Findings = append(h.Findings, Finding{Verdict: v, How: "package " + image.Name, Installed: []string{image.Name}})
	case running != "" || image != nil:
		display := running
		if display == "" {
			display = newest
		}
		h.Findings = append(h.Findings, upstreamKernel(display, index, o))
	}
	if h.Reboot {
		h.Notes = append(h.Notes, "reboot-needed:"+newest)
	}
	return h, nil
}

func kernelMatches(family string, image Package, running string) bool {
	_, uname := kernelImage(family, image)
	return uname == running || strings.HasPrefix(running, uname)
}

// chooseKernel picks the image to judge: the one running, if a package explains it, else the newest installed. It also
// names the newest, for the reboot note.
func chooseKernel(family string, images []Package, running string) (*Package, string) {
	if len(images) == 0 {
		return nil, ""
	}
	sorted := append([]Package(nil), images...)
	sort.SliceStable(sorted, func(i, j int) bool { return Compare(family, sorted[i].SourceVersion, sorted[j].SourceVersion) > 0 })
	_, newest := kernelImage(family, sorted[0])
	if running != "" {
		for i := range sorted {
			if kernelMatches(family, sorted[i], running) {
				return &sorted[i], newest
			}
		}
		return nil, newest // what runs is no package here
	}
	return &sorted[0], newest
}

func upstreamKernel(v string, index *Index, o Options) Finding {
	version := v
	if !IsPlainKernel(v) {
		reason := "vendor-kernel"
		return Finding{Verdict: core.Verdict{Product: "linux", Version: &version, Status: core.Unknown, Reason: &reason, Advisories: []core.VerdictAdvisory{}}, How: "uname"}
	}
	lines, _ := LoadFile("linux-kernel", o.Offline, o.UserAgent)
	out := core.Verdict{Product: "linux", Version: &version, Status: core.OK, Advisories: []core.VerdictAdvisory{}}
	if lines == nil {
		reason := "line-not-listed"
		out.Status, out.Reason = core.Unknown, &reason
		return Finding{Verdict: out, How: "kernel.org"}
	}
	for _, c := range ReadKernel(lines) {
		if c.Affected(v) {
			out.Advisories = append(out.Advisories, core.VerdictAdvisory{ID: c.ID, Severity: "unknown", URL: "https://www.cve.org/CVERecord?id=" + c.ID})
		}
	}
	sort.SliceStable(out.Advisories, func(i, j int) bool { return out.Advisories[i].ID > out.Advisories[j].ID })
	lineEnded := false
	fix := ""
	if index != nil {
		ls := index.Lines["linux"]
		found := false
		for _, l := range ls {
			if l.Cycle == kernelLine(v) {
				found = true
				lineEnded = l.EOL != "" && l.EOL <= o.Today
				if !lineEnded {
					fix = l.Latest
				}
			}
		}
		if lineEnded || !found {
			for _, l := range ls { // newest first: the oldest still-supported line that is newer
				if (l.EOL == "" || l.EOL > o.Today) && compareKernel(l.Cycle, kernelLine(v)) > 0 {
					fix = l.Latest
				}
			}
		}
	}
	switch {
	case len(out.Advisories) > 0:
		out.Status = core.Vulnerable
	case lineEnded:
		out.Status = core.Unsupported
	}
	if out.Status != core.OK {
		if fix != "" && compareKernel(fix, v) > 0 {
			out.Fix = &fix
		} else {
			out.NoFix = true
		}
	}
	return Finding{Verdict: out, How: "kernel.org, by version number"}
}
