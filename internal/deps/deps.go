// Package deps reads the packages a lockfile resolves: npm (five lockfiles), crates.io (Cargo.lock) and Go modules
// (go.sum, go.mod). Text only: nothing is run, nothing is fetched.
package deps

import (
	"strings"

	"github.com/rasoat/rasoat/internal/core"
)

// Ecosystems, as the data files and the purl in a report name them.
const (
	NPM   = "npm"
	Cargo = "cargo"
	Go    = "go"
)

// Purl is the product string of a package: pkg:npm/<name>, pkg:cargo/<name>, pkg:golang/<module>.
func Purl(eco, name string) string {
	if eco == Go {
		eco = "golang"
	}
	return "pkg:" + eco + "/" + name
}

// Pkg is one resolved package in one lockfile. Rule is the user's detector that read it, when no lockfile did.
type Pkg struct {
	Eco, Name, Version, File string
	Rule                     string
}

var parsers = map[string]func(string) []Pkg{
	"package-lock.json":   packageLock,
	"npm-shrinkwrap.json": packageLock,
	"pnpm-lock.yaml":      pnpmLock,
	"yarn.lock":           yarnLock,
	"bun.lock":            bunLock,
	"Cargo.lock":          cargoLock,
	"go.sum":              goSum,
	"go.mod":              goMod,
}

// Reads says whether a file of this name is one the package readers understand.
func Reads(name string) bool { return parsers[name] != nil }

// Parse reads one lockfile's text. Each (ecosystem, name, version) comes back once per file. A version that is not a
// version (a git URL, a workspace link, a tarball) is not a registry package and is left out.
func Parse(name, text, file string) []Pkg {
	parse := parsers[name]
	if parse == nil {
		return nil
	}
	seen := map[Pkg]bool{}
	var out []Pkg
	for _, p := range parse(text) {
		p.File = file
		if p.Name == "" || !core.ValidVersion(p.Version) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// splitSpec splits "name@1.2.3", "@scope/name@1.2.3" and the alias form "alias@npm:real@1.2.3" (and "name@npm:1.2.3").
func splitSpec(spec string) (name, version string) {
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return "", ""
	}
	name, version = spec[:at], strings.TrimPrefix(spec[at+1:], "npm:")
	if i := strings.Index(name, "@npm:"); i > 0 {
		name = name[i+len("@npm:"):]
	}
	return strings.TrimSuffix(name, "@npm:"), version
}
