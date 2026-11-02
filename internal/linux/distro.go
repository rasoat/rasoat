package linux

import "strings"

// Distro is what /etc/os-release says, and how far this program can judge it.
type Distro struct {
	ID      string // ubuntu, debian, rhel, almalinux, rocky, alpine, opensuse-leap, sles, centos, fedora, amzn, ...
	Name    string // PRETTY_NAME
	Version string // VERSION_ID
	Family  string // deb, rpm, apk; empty when the package database is one this program does not read
	File    string // the data file for this release; empty when no per-package advisories are published for it
	Line    string // the release line in end-of-life data: "22.04", "12", "9", "3.20"
	Cycle   string // the product's name in end-of-life data
}

func parseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

func firstPart(v string, n int) string {
	p := strings.Split(v, ".")
	return strings.Join(p[:min(n, len(p))], ".")
}

// DetectDistro reads os-release. nil: no such file, so this is not a Linux root.
func DetectDistro(root string) *Distro {
	var text []byte
	var err error
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		if text, err = readFile(root, p); err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	f := parseOSRelease(string(text))
	d := &Distro{ID: strings.ToLower(f["ID"]), Name: f["PRETTY_NAME"], Version: f["VERSION_ID"]}
	major := firstPart(d.Version, 1)
	switch d.ID {
	case "ubuntu":
		d.Family, d.Line, d.Cycle, d.File = "deb", firstPart(d.Version, 2), "ubuntu", "ubuntu-"+firstPart(d.Version, 2)
	case "debian":
		d.Family, d.Line, d.Cycle = "deb", major, "debian"
		if major != "" {
			d.File = "debian-" + major
		}
	case "almalinux":
		d.Family, d.Line, d.Cycle, d.File = "rpm", major, "almalinux", "almalinux-"+major
	case "rocky":
		d.Family, d.Line, d.Cycle, d.File = "rpm", major, "rocky-linux", "rocky-"+major
	case "rhel":
		d.Family, d.Line, d.Cycle, d.File = "rpm", major, "rhel", "rhel-"+major
	case "centos":
		d.Family, d.Line, d.Cycle = "rpm", major, "centos"
	case "fedora":
		d.Family, d.Line, d.Cycle = "rpm", major, "fedora"
	case "amzn":
		d.Family, d.Line, d.Cycle = "rpm", major, "amazon-linux"
	case "ol":
		d.Family, d.Line, d.Cycle = "rpm", major, "oracle-linux"
	case "alpine":
		d.Family, d.Line, d.Cycle, d.File = "apk", firstPart(d.Version, 2), "alpine-linux", "alpine-"+firstPart(d.Version, 2)
	case "opensuse-leap":
		d.Family, d.Line, d.Cycle, d.File = "rpm", firstPart(d.Version, 2), "opensuse", "opensuse-leap-"+firstPart(d.Version, 2)
	case "opensuse-tumbleweed":
		d.Family, d.File = "rpm", "opensuse-tumbleweed"
	case "sles", "sled":
		d.Family, d.Line, d.Cycle, d.File = "rpm", firstPart(d.Version, 2), "sles", "sles-"+firstPart(d.Version, 2)
	}
	return d
}
