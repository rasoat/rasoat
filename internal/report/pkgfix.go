package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
)

// What to change for a package a lockfile resolves, and for an image a file names. Like the rest of the plan this is
// knowledge: it reads the project's package.json to know whether a package is a direct dependency, and runs nothing.
//
// A package name comes from a downloaded file or a stranger's lockfile and ends up in a command, so only a name of the
// plain shape its ecosystem allows gets there, and it never starts with '-'.
var (
	npmName   = core.NewRe(`^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$`)
	cargoName = core.NewRe(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	goModule  = core.NewRe(`^[A-Za-z0-9][A-Za-z0-9._~/-]*$`)
	imageText = core.NewRe(`^[A-Za-z0-9][A-Za-z0-9./:_@${}-]*$`)
)

const maxManifest = 4 << 20

// readProject reads a file of the scanned project, relative to its directory.
func readProject(root, rel string) (string, bool) {
	if root == "" {
		return "", false
	}
	file := filepath.Join(root, filepath.FromSlash(rel))
	st, err := os.Stat(file)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxManifest {
		return "", false
	}
	b, err := os.ReadFile(file)
	return string(b), err == nil
}

// declares says whether package.json (text) lists name as a dependency of its own.
func declares(text, name string) bool {
	var p map[string]any
	if json.Unmarshal([]byte(text), &p) != nil {
		return false
	}
	for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		if m, ok := p[k].(map[string]any); ok {
			if _, has := m[name]; has {
				return true
			}
		}
	}
	return false
}

// manager is the package manager a npm-ecosystem lockfile belongs to. A yarn.lock with a __metadata block is berry's.
func manager(lock, text string) string {
	switch lock {
	case "pnpm-lock.yaml":
		return "pnpm"
	case "bun.lock":
		return "bun"
	case "yarn.lock":
		if strings.Contains(text[:min(len(text), 4096)], "__metadata:") {
			return "yarn-berry"
		}
		return "yarn"
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm"
	}
	return ""
}

// overrides says how each manager pins a package that no package.json of the project asks for.
func overrides(mgr, name, to string) string {
	pin := "the fixed version"
	if plainVersion.MatchString(to) {
		pin = to
	}
	switch mgr {
	case "pnpm":
		return fmt.Sprintf(`Add "pnpm": {"overrides": {"%s": "%s"}} to the root package.json, then run pnpm install and commit the lockfile.`, name, pin)
	case "yarn", "yarn-berry":
		return fmt.Sprintf(`Add "resolutions": {"%s": "%s"} to the root package.json, then run yarn install and commit the lockfile.`, name, pin)
	case "bun":
		return fmt.Sprintf(`Add "overrides": {"%s": "%s"} to the root package.json, then run bun install and commit the lockfile.`, name, pin)
	}
	return fmt.Sprintf(`Add "overrides": {"%s": "%s"} to the root package.json, then run npm install and commit the lockfile.`, name, pin)
}

// pkgChange is the change for one lockfile that resolves a vulnerable package. cur is the version it resolves now.
func pkgChange(product string, cur *string, file, to, root string) Change {
	eco, name, _ := strings.Cut(strings.TrimPrefix(product, "pkg:"), "/")
	lock, dir := path.Base(file), path.Dir(file)
	plain := plainVersion.MatchString(to)
	run := func(c string) *string {
		if plain {
			return &c
		}
		return nil
	}
	generic := Change{File: file, Cwd: &dir, How: fmt.Sprintf("Move the package to %s in %s, then install and commit the lockfile.", to, lock)}
	if !plain {
		generic.How = fmt.Sprintf("Move the package to the fixed version in %s, then install and commit the lockfile.", lock)
	}
	switch {
	case eco == "npm" && npmName.MatchString(name):
		text, _ := readProject(root, file)
		mgr := manager(lock, text)
		if mgr == "" {
			return generic
		}
		pkgJSON, ok := readProject(root, path.Join(dir, "package.json"))
		if !ok || !declares(pkgJSON, name) {
			// Not asked for by the package.json beside the lockfile: another package pulls it in, so no one command moves it.
			return Change{File: file, Cwd: &dir, How: overrides(mgr, name, to) + " Or update the package that depends on it, or the workspace package that declares it."}
		}
		var cmd, via string
		switch mgr {
		case "pnpm":
			cmd, via = "pnpm update "+name+"@"+to, "pnpm"
		case "yarn-berry":
			cmd, via = "yarn up "+name+"@"+to, "yarn"
		case "yarn":
			cmd, via = "yarn upgrade "+name+"@"+to, "yarn"
		case "bun":
			cmd, via = "bun update "+name+"@"+to, "bun"
		default:
			cmd, via = "npm install "+name+"@"+to, "npm"
		}
		return Change{file, &dir, run(cmd), fmt.Sprintf("Move %s to %s with %s, in the package that declares it, then commit the lockfile.", name, to, via)}
	case eco == "cargo" && lock == "Cargo.lock" && cargoName.MatchString(name):
		spec := name
		if cur != nil && plainVersion.MatchString(*cur) {
			spec += "@" + *cur // a crate can be resolved at two versions; name the one this row is
		}
		return Change{file, &dir, run("cargo update -p " + spec + " --precise " + to),
			fmt.Sprintf("Run it where Cargo.lock is. If cargo says %s does not satisfy a requirement, raise that requirement in Cargo.toml first; if another crate pulls %s in, update that crate.", to, name)}
	case eco == "golang" && (lock == "go.sum" || lock == "go.mod") && goModule.MatchString(name):
		return Change{file, &dir, run("go get " + name + "@v" + to + " && go mod tidy"),
			fmt.Sprintf("Run it where go.mod is. It moves %s to v%s, then tidies go.mod and go.sum; commit both.", name, to)}
	}
	return generic
}

// sourceRef is the image reference in a source that reads `Dockerfile (node:22)`: empty when the source has none, or when
// it is a CI pin, which is a version key and not an image.
func sourceRef(source string) string {
	_, ref, ok := strings.Cut(source, " (")
	ref = strings.TrimSuffix(ref, ")")
	if !ok || strings.Contains(ref, "-version:") || !imageText.MatchString(ref) {
		return ""
	}
	return ref
}

// imageChange is an edit of the line that names the image. The file says which tags the project uses, so no command can.
func imageChange(file, ref, to string) Change {
	base := path.Base(file)
	line := "the FROM line"
	if strings.Contains(base, "compose") {
		line = "the image: line"
	}
	cwd := path.Dir(file)
	return Change{File: file, Cwd: &cwd, How: fmt.Sprintf("In %s, change the tag of %s on %s to %s (keep a variant suffix such as -alpine if it has one), then pull the image and restart what runs it.", base, ref, line, to)}
}
