package linux

import (
	"regexp"
	"strconv"
	"strings"
)

// kernelVersion is x.y[.z] as numbers, ignoring what follows.
func kernelParts(v string) ([3]int, bool) {
	var out [3]int
	f := strings.Split(strings.SplitN(v, "-", 2)[0], ".")
	if len(f) < 2 {
		return out, false
	}
	for i := 0; i < len(f) && i < 3; i++ {
		n, err := strconv.Atoi(f[i])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func compareKernel(a, b string) int {
	x, _ := kernelParts(a)
	y, _ := kernelParts(b)
	for i := range x {
		if x[i] != y[i] {
			return sign(x[i] - y[i])
		}
	}
	return 0
}

// inRange: at or above from, and below an exact bound, or on the line 5.15.*, or * for everything above.
func inRange(v, from, to string) bool {
	if compareKernel(v, from) < 0 {
		return false
	}
	switch {
	case to == "*":
		return true
	case strings.HasSuffix(to, ".*"):
		return strings.HasPrefix(v+".", strings.TrimSuffix(to, "*"))
	case strings.HasPrefix(to, "<"):
		return compareKernel(v, to[1:]) < 0
	}
	return compareKernel(v, to) <= 0
}

// Affected says whether an upstream kernel version carries this CVE: at or above where it came in, in no fixed range.
func (c *KernelCVE) Affected(v string) bool {
	if compareKernel(v, c.Introduced) < 0 {
		return false
	}
	for _, r := range c.Unaffected {
		from, to, ok := strings.Cut(r, ":")
		if ok && inRange(v, from, to) {
			return false
		}
	}
	return true
}

// A plain kernel.org number: x.y or x.y.z, perhaps -rcN. Anything with more after it is a vendor's build, whose backports
// make the number say nothing about which fixes it has.
var plainKernel = regexp.MustCompile(`^\d+\.\d+(\.\d+)?(-rc\d+)?\+?$`)

// IsPlainKernel is true when the upstream data may judge this version by its number.
func IsPlainKernel(v string) bool { return plainKernel.MatchString(v) }

func kernelLine(v string) string { return firstPart(v, 2) }

// isKernelBinary: packages that are the kernel or built from it. They are judged once, as the kernel, not package by
// package: a machine keeps old kernels installed, and headers say nothing about what runs.
func isKernelBinary(family, name string) bool {
	switch family {
	case "deb":
		for _, p := range []string{"linux-image-", "linux-modules-", "linux-headers-", "linux-libc-dev", "linux-tools-", "linux-cloud-tools-", "linux-buildinfo-", "linux-source-", "linux-doc", "linux-kbuild-", "linux-compiler-"} {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
	case "rpm":
		return name == "kernel" || strings.HasPrefix(name, "kernel-")
	case "apk":
		return name == "linux-lts" || name == "linux-virt" || name == "linux-edge" || name == "linux-rpi" || name == "linux-stable"
	}
	return false
}

// kernelImage is the package that holds a bootable kernel, and the uname -r it would report ("" when it cannot be told).
func kernelImage(family string, p Package) (bool, string) {
	switch family {
	case "deb":
		if strings.HasPrefix(p.Name, "linux-image-") && len(p.Name) > 12 && isDigit(p.Name[12]) && !strings.HasSuffix(p.Name, "-dbg") && !strings.HasSuffix(p.Name, "-dbgsym") {
			return true, strings.TrimPrefix(p.Name, "linux-image-")
		}
	case "rpm":
		_, evr := splitEpoch(p.Version)
		switch p.Name {
		case "kernel-core", "kernel", "kernel-uek", "kernel-uek-core", "kernel-rt", "kernel-rt-core":
			return true, evr // uname -r is version-release, then .x86_64: matched by prefix
		case "kernel-default", "kernel-default-base", "kernel-azure":
			// SUSE: package 6.4.0-150600.23.103.1 reports 6.4.0-150600.23.103-default.
			flavour := strings.TrimSuffix(strings.TrimPrefix(p.Name, "kernel-"), "-base")
			head, _ := cutLast(evr, '.')
			return true, head + "-" + flavour
		}
	case "apk":
		if isKernelBinary("apk", p.Name) {
			flavour := strings.TrimPrefix(p.Name, "linux-")
			version, rel := cutLast(p.Version, '-')
			return true, version + "-" + strings.TrimPrefix(rel, "r") + "-" + flavour // 6.6.31-r0 reports 6.6.31-0-lts
		}
	}
	return false, ""
}

// kernelSource maps a kernel image to the source package its advisories name. Debian and Ubuntu sign their images in a
// wrapper source package: linux-signed-amd64 6.1.106+3 is linux 6.1.106-3, linux-signed-hwe-6.8 is linux-hwe-6.8.
func kernelSource(family string, p Package) (string, string) {
	if family != "deb" {
		return p.Source, p.SourceVersion
	}
	src, ver := p.Source, p.SourceVersion
	if strings.HasPrefix(src, "linux-signed") {
		rest := strings.TrimPrefix(src, "linux-signed")
		switch rest {
		case "", "-amd64", "-arm64", "-i386", "-ppc64el", "-s390x", "-armhf":
			src = "linux"
		default:
			src = "linux" + rest
		}
		if i := strings.LastIndexByte(ver, '+'); i > 0 && !strings.Contains(ver[i:], "-") {
			ver = ver[:i] + "-" + ver[i+1:]
		}
	}
	return src, ver
}
