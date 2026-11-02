// Package project finds what a directory says it runs. Files are read as text and never executed.
package project

import (
	"encoding/json"
	"github.com/rasoat/rasoat/internal/core"
	"sort"
	"strings"
)

// Pin is a version a file states: exact, or as declared ("^14.0.0", "20", "lts/*"), which a verdict answers "not exact".
type Pin struct {
	Product string
	Version string
}

func pins(product string, versions []string) []Pin {
	out, seen := []Pin{}, map[string]bool{}
	for _, v := range versions {
		if !seen[v] {
			seen[v] = true
			out = append(out, Pin{product, v})
		}
	}
	return out
}

func parseJSON(text string) map[string]any {
	var v map[string]any
	if json.Unmarshal([]byte(text), &v) != nil {
		return nil
	}
	return v
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
func str(v any) string {
	s, _ := v.(string)
	return s
}
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var lockPath = core.NewRe(`(^|/)node_modules/next$`)

// PackageLock reads npm's v2/v3 `packages` (every nested copy) and v1 `dependencies` (recursive).
func PackageLock(text string) []Pin {
	lock := parseJSON(text)
	var found []string
	if packages := obj(lock["packages"]); packages != nil {
		for _, path := range sortedKeys(packages) {
			if v := str(obj(packages[path])["version"]); v != "" && lockPath.MatchString(path) {
				found = append(found, v)
			}
		}
		return pins("next", found)
	}
	var walk func(map[string]any)
	walk = func(deps map[string]any) {
		for _, name := range sortedKeys(deps) {
			d := obj(deps[name])
			if v := str(d["version"]); name == "next" && v != "" {
				found = append(found, v)
			}
			walk(obj(d["dependencies"]))
		}
	}
	walk(obj(lock["dependencies"]))
	return pins("next", found)
}

func allFirstGroups(re *core.Re, text string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

var (
	pnpmRe = core.NewRe(`(?m)^\s*['"]?/?next[@/](\d+\.\d+\.\d+[^:('"\s]*)`)
	yarnRe = core.NewRe(`(?m)^"?next@[^\n]*:\r?\n\s+version:?\s+"?([^"\s]+)`)
	bunRe  = core.NewRe(`\["next@(\d[^"]*)"`)
	wpRe   = core.NewRe(`(?m)^\$wp_version\s*=\s*['"]([^'"]+)['"]`)
	pmRe   = core.NewRe(`^bun@(\d+\.\d+\.\d+)`)
	vPin   = core.NewRe(`^v(\d)`)
)

// PnpmLock: `next@14.2.3(react@18):` (v9), `/next@14.2.3:` (v6), `/next/14.2.3:` (v5).
func PnpmLock(text string) []Pin { return pins("next", allFirstGroups(pnpmRe, text)) }

// YarnLock: a `next@...:` block header followed by `version "x"` (v1) or `version: x` (berry).
func YarnLock(text string) []Pin { return pins("next", allFirstGroups(yarnRe, text)) }

// BunLock: `"next": ["next@15.0.0", "", ...]`, any nested key.
func BunLock(text string) []Pin { return pins("next", allFirstGroups(bunRe, text)) }

var wpPackages = map[string]bool{"roots/wordpress": true, "roots/wordpress-no-content": true, "johnpbloch/wordpress": true, "johnpbloch/wordpress-core": true}

// ComposerLock: the package that installs WordPress core (Bedrock and similar).
func ComposerLock(text string) []Pin {
	packages, _ := parseJSON(text)["packages"].([]any)
	var found []string
	for _, p := range packages {
		m := obj(p)
		if v := str(m["version"]); wpPackages[str(m["name"])] && v != "" {
			found = append(found, strings.TrimPrefix(v, "v"))
		}
	}
	return pins("wordpress", found)
}

// WpVersionPhp reads WordPress core's own record of its version with a pattern; it is never run.
func WpVersionPhp(text string) []Pin { return pins("wordpress", allFirstGroups(wpRe, text)) }

// InstalledNext: node_modules/next/package.json, what is installed here, which can differ from the lockfile.
func InstalledNext(text string) []Pin {
	p := parseJSON(text)
	if v := str(p["version"]); str(p["name"]) == "next" && v != "" {
		return pins("next", []string{v})
	}
	return []Pin{}
}

// Declared reads package.json: a Next.js range (kept only when no lockfile answers) and Bun's exact version.
func Declared(text string) (next string, out []Pin) {
	p := parseJSON(text)
	out = []Pin{}
	nx, ok := obj(p["dependencies"])["next"]
	if !ok || nx == nil {
		nx = obj(p["devDependencies"])["next"]
	}
	next = str(nx)
	if m := pmRe.FindStringSubmatch(str(p["packageManager"])); m != nil {
		out = pins("bun", []string{m[1]})
	}
	return next, out
}

func pinFile(product string) func(string) []Pin {
	return func(text string) []Pin {
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				return pins(product, []string{vPin.ReplaceAllString(l, "$1")})
			}
		}
		return []Pin{}
	}
}

var tools = map[string]string{"nodejs": "node", "node": "node", "php": "php", "bun": "bun"}

// ToolVersions reads asdf/mise .tool-versions: `nodejs 20.11.0`.
func ToolVersions(text string) []Pin {
	out := []Pin{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && tools[f[0]] != "" {
			out = append(out, Pin{tools[f[0]], f[1]})
		}
	}
	return out
}

// Manifests maps a file name, found anywhere in the walk, to its parser.
var Manifests = map[string]func(string) []Pin{
	"package-lock.json":   PackageLock,
	"npm-shrinkwrap.json": PackageLock,
	"pnpm-lock.yaml":      PnpmLock,
	"yarn.lock":           YarnLock,
	"bun.lock":            BunLock,
	"composer.lock":       ComposerLock,
	".nvmrc":              pinFile("node"),
	".node-version":       pinFile("node"),
	".php-version":        pinFile("php"),
	".bun-version":        pinFile("bun"),
	".tool-versions":      ToolVersions,
}

var nextLocks = []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
