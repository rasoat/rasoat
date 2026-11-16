package deps

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The lockfiles under fixtures/ were written by their own tools (npm, pnpm, yarn 1 and berry, bun, cargo, go).
func parseFixture(t *testing.T, dir, name string) []Pkg {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return Parse(name, string(b), dir+"/"+name)
}

func has(pkgs []Pkg, eco, name, version string) bool {
	return slices.ContainsFunc(pkgs, func(p Pkg) bool { return p.Eco == eco && p.Name == name && p.Version == version })
}

func TestEveryNpmLockfileYieldsTheSamePackages(t *testing.T) {
	for _, c := range [][3]string{{"bun", "bun.lock", "8.4.31"}, {"pnpm", "pnpm-lock.yaml", "8.4.31"}, {"yarn-berry", "yarn.lock", "8.4.31"}, {"yarn-v1", "yarn.lock", "8.4.14"}} {
		pkgs := parseFixture(t, c[0], c[1])
		if !has(pkgs, NPM, "postcss", c[2]) {
			t.Errorf("%s: no postcss@%s in %d packages", c[0], c[2], len(pkgs))
		}
		if !has(pkgs, NPM, "next", map[string]string{"bun": "15.0.0", "pnpm": "13.5.11", "yarn-berry": "16.0.0", "yarn-v1": "12.3.7"}[c[0]]) {
			t.Errorf("%s: no next", c[0])
		}
		if len(pkgs) < 20 {
			t.Errorf("%s: only %d packages", c[0], len(pkgs))
		}
		for _, p := range pkgs {
			if strings.ContainsAny(p.Name+p.Version, " \t\n\"") || p.File == "" {
				t.Errorf("%s: bad package %+v", c[0], p)
			}
		}
	}
	if pkgs := parseFixture(t, "npm", "package-lock.json"); !has(pkgs, NPM, "@next/env", "14.2.3") || !has(pkgs, NPM, "next", "14.2.3") {
		t.Errorf("package-lock v3: %+v", pkgs)
	}
}

func TestScopedNamesAndPeerSuffixes(t *testing.T) {
	pnpm := "lockfileVersion: '9.0'\n\npackages:\n\n  '@next/env@13.5.11':\n    resolution: {integrity: x}\n\n  react-dom@18.3.1(react@18.3.1):\n    resolution: {integrity: x}\n\nsnapshots:\n\n  'not-a-package@9.9.9':\n    dependencies: {}\n"
	got := Parse("pnpm-lock.yaml", pnpm, "p")
	if !has(got, NPM, "@next/env", "13.5.11") || !has(got, NPM, "react-dom", "18.3.1") || len(got) != 2 {
		t.Errorf("pnpm v9: %+v", got)
	}
	v5 := "packages:\n\n  /@babel/core/7.20.0_peer@1.0.0:\n    resolution: {integrity: x}\n  /lodash/4.17.15:\n    resolution: {integrity: x}\n"
	got = Parse("pnpm-lock.yaml", v5, "p")
	if !has(got, NPM, "@babel/core", "7.20.0") || !has(got, NPM, "lodash", "4.17.15") {
		t.Errorf("pnpm v5: %+v", got)
	}
}

// Only a registry package is judged: its name means the registry's package of that name. A git URL, a link or a workspace
// is somebody's own code.
func TestNonRegistryPackagesAreLeftOut(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"app"},
	  "packages/ui":{"name":"ui","version":"1.0.0"},
	  "node_modules/ui":{"resolved":"packages/ui","link":true},
	  "node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
	  "node_modules/from-git":{"version":"1.0.0","resolved":"git+ssh://git@example.com/x/from-git.git#abc"},
	  "node_modules/a/node_modules/lodash":{"version":"3.10.1","resolved":"https://registry.npmjs.org/lodash/-/lodash-3.10.1.tgz"},
	  "node_modules/alias":{"name":"real-name","version":"2.0.0","resolved":"https://registry.npmjs.org/real-name/-/real-name-2.0.0.tgz"}}}`
	got := Parse("package-lock.json", lock, "l")
	for _, w := range [][2]string{{"lodash", "4.17.15"}, {"lodash", "3.10.1"}, {"real-name", "2.0.0"}} {
		if !has(got, NPM, w[0], w[1]) {
			t.Errorf("missing %v in %+v", w, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("want 3 packages, got %+v", got)
	}
	v1 := `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"npm:real@2.0.0"}}},"g":{"version":"github:x/g#abc"}}}`
	got = Parse("npm-shrinkwrap.json", v1, "l")
	if !has(got, NPM, "a", "1.0.0") || !has(got, NPM, "real", "2.0.0") || len(got) != 2 {
		t.Errorf("v1: %+v", got)
	}
	bun := `{
  "lockfileVersion": 1,
  "workspaces": {"": {"name": "app",},},
  "packages": {
    "app": ["app@workspace:."],
    "lodash": ["lodash@4.17.15", "", {}, "sha512-x"],
    "x-alias": ["x-alias@npm:real@1.2.3", "", {}, "sha512-y"],
    "gitdep": ["gitdep@github:user/repo#abc", {}, "abc"],
  }
}`
	got = Parse("bun.lock", bun, "b")
	if !has(got, NPM, "lodash", "4.17.15") || !has(got, NPM, "real", "1.2.3") || len(got) != 2 {
		t.Errorf("bun: %+v", got)
	}
}

func TestCargoLockReadsOnlyRegistryCrates(t *testing.T) {
	got := parseFixture(t, "cargo", "Cargo.lock")
	if !has(got, Cargo, "tokio", "1.53.1") || !has(got, Cargo, "bytes", "1.12.1") || len(got) != 2 {
		t.Errorf("want tokio and bytes only (the path crate and the git crate are not on crates.io): %+v", got)
	}
}

func TestGoSumDropsGoModLinesAndGoModIsTheFallback(t *testing.T) {
	got := parseFixture(t, "go", "go.sum")
	if !has(got, Go, "github.com/golang-jwt/jwt/v5", "v5.3.1") {
		t.Errorf("go.sum: %+v", got)
	}
	for _, p := range got {
		if strings.HasSuffix(p.Version, "/go.mod") {
			t.Errorf("a /go.mod line came through: %+v", p)
		}
	}
	mod := parseFixture(t, "go", "go.mod")
	if !has(mod, Go, "golang.org/x/net", "v0.54.0") || !has(mod, Go, "cloud.google.com/go/compute/metadata", "v0.3.0") || len(mod) != 3 {
		t.Errorf("go.mod: %+v", mod)
	}
}

func TestDuplicatesCollapseWithinAFile(t *testing.T) {
	sum := "m v1.0.0 h1:a\nm v1.0.0 h1:a\nm v1.0.0/go.mod h1:b\n"
	if got := Parse("go.sum", sum, "f"); len(got) != 1 {
		t.Errorf("%+v", got)
	}
}
