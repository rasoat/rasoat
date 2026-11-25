package linux

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Where a package came from. A vendor repo (Sury, PGDG, NodeSource, MariaDB, Proxmox) ships builds under the distro's own
// source names, and its version number says nothing about the distro's fixes: Sury's php8.3 8.3.36 sorts above Ubuntu's
// 8.3.6-0ubuntu0.24.04.x whatever either fixed. Comparing them would say "clean" about a build the distro never saw. So the
// origin is decided first, from files only, and a vendor package is never compared with the distro's advisories.

// distroOrigin: the Origin of a Release file for the distro's own archive. A mirror keeps it, so no hostname matters.
func distroOrigin(o string) bool { return o == "Ubuntu" || o == "Debian" }

// The rpm Vendor tag of the distro's own builds, lower-case fragments.
var distroVendors = []string{"red hat", "almalinux", "rocky", "suse", "amazon", "oracle", "fedora", "centos"}

// rpmVendor reads a header's Vendor. decided false: the header says nothing (empty, "(none)"), so the markers may speak.
// decided true with an empty vendor: a distro build.
func rpmVendor(v string) (vendor string, decided bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == "(none)" {
		return "", false
	}
	low := strings.ToLower(v)
	for _, d := range distroVendors {
		if strings.Contains(low, d) {
			return "", true
		}
	}
	return v, true
}

// markers are the fallback when no list decides (absent, compressed, or the version no longer listed): what a vendor
// writes into its version strings. First match wins.
var markers = []struct {
	re     *regexp.Regexp
	vendor string
}{
	{regexp.MustCompile(`deb\.sury\.org`), "sury"},
	{regexp.MustCompile(`[.+~]pgdg`), "pgdg"},
	{regexp.MustCompile(`nodesource`), "nodesource"},
	{regexp.MustCompile(`\+maria~`), "mariadb"},
	{regexp.MustCompile(`\+pmx`), "proxmox"},
	{regexp.MustCompile(`[.+~]remi`), "remi"},
	{regexp.MustCompile(`^\d+\.\d+\.\d+-\d+~[a-z]+$`), "nginx"}, // nginx.org: 1.31.8-1~noble. The product also needs source nginx.
}

func markerVendor(version string) string {
	for _, m := range markers {
		if m.re.MatchString(version) {
			return m.vendor
		}
	}
	return ""
}

// aptOrigins sets Vendor and Decided from apt's lists: /var/lib/apt/lists/<prefix>_<component>_binary-<arch>_Packages
// pairs with <prefix>_InRelease or <prefix>_Release, whose Origin names the archive. An installed (name, version) is the
// distro's when a distro archive lists that exact version, a vendor's when only a vendor's archive does. Compressed lists
// (docker images keep .lz4) cannot be read with the standard library, and a list with no release file cannot say whose it
// is: those decide nothing, and the markers speak.
//
// Backports are the distro's builds, but its security advisories do not track that pocket, so a version listed only there
// is not judged: "<Origin> backports".
func aptOrigins(root string, pkgs []Package) (notes []string) {
	names, truncated, err := listDir(root, "var/lib/apt/lists")
	if err != nil {
		return nil
	}
	if truncated {
		notes = append(notes, tooManyFiles)
	}
	have := map[string]bool{}
	for _, p := range pkgs {
		have[p.Name+" "+p.Version] = true
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	listed := map[string]string{} // "name version" -> origin; "" when the distro lists it
	for _, n := range names {
		if !strings.HasSuffix(n, "_Packages") {
			continue
		}
		prefix, ok := releasePrefix(n)
		if !ok {
			continue
		}
		rel := ""
		for _, suffix := range []string{"_InRelease", "_Release"} {
			if set[prefix+suffix] {
				rel = prefix + suffix
				break
			}
		}
		if rel == "" {
			continue
		}
		origin := readOrigin(root, "var/lib/apt/lists/"+rel)
		if origin == "" {
			continue
		}
		label := origin
		if strings.HasPrefix(origin, ".") { // NodeSource writes "Origin: . nodistro": the archive's host names it better
			label = prefix[:strings.Index(prefix, "_")]
		}
		if strings.HasSuffix(prefix, "-backports") {
			label += " backports"
		} else if distroOrigin(origin) {
			label = ""
		}
		scanPackages(root, "var/lib/apt/lists/"+n, have, func(key string) {
			if cur, seen := listed[key]; !seen || (cur != "" && label == "") {
				listed[key] = label // the distro's own archive wins over a vendor's that lists the same version
			}
		})
	}
	for i := range pkgs {
		if label, ok := listed[pkgs[i].Name+" "+pkgs[i].Version]; ok {
			pkgs[i].Vendor, pkgs[i].Decided = label, "apt-lists"
		}
	}
	return notes
}

// releasePrefix is the file-name prefix a Packages list shares with its release file: everything through the suite,
// "archive.ubuntu.com_ubuntu_dists_noble-updates" from "..._dists_noble-updates_main_binary-amd64_Packages".
func releasePrefix(name string) (string, bool) {
	i := strings.Index(name, "_dists_")
	if i < 0 {
		return "", false
	}
	rest := name[i+len("_dists_"):]
	j := strings.Index(rest, "_")
	if j < 0 {
		return "", false
	}
	return name[:i+len("_dists_")+j], true
}

// readOrigin: the Origin field of a Release or InRelease, in the header only (a signed one starts with PGP lines).
func readOrigin(root, rel string) string {
	f, err := openFile(root, rel)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxSmallText))
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "Origin:"); ok {
			return strings.TrimSpace(v)
		}
		if strings.HasPrefix(line, "MD5Sum:") || strings.HasPrefix(line, "SHA256:") {
			break
		}
	}
	return ""
}

// scanPackages calls found("name version") for each stanza of a plain Packages file whose pair is wanted.
func scanPackages(root, rel string, wanted map[string]bool, found func(string)) {
	f, err := openCapped(root, rel, maxAptList)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	var name, version string
	flush := func() {
		if k := name + " " + version; name != "" && wanted[k] {
			found(k)
		}
		name, version = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(line[9:])
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(line[9:])
		}
	}
	flush()
}

// assignOrigins sets Vendor and Decided on every package: the lists or the rpm header first, then the version markers
// for what they left undecided. A package nothing decides stays the distro's, as before.
func assignOrigins(root, family string, pkgs []Package) (notes []string) {
	if family == "deb" {
		notes = aptOrigins(root, pkgs)
	}
	for i := range pkgs {
		if pkgs[i].Decided != "" {
			continue
		}
		if v := markerVendor(pkgs[i].Version); v != "" {
			if v == "nginx" && pkgs[i].Name != "nginx" && !strings.HasPrefix(pkgs[i].Name, "nginx-") {
				continue // the pattern is too common to claim any other package
			}
			pkgs[i].Vendor, pkgs[i].Decided = v, "version-marker"
		}
	}
	return notes
}
