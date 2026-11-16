package project

import (
	"bytes"
	"os"
	"path"
	"path/filepath"

	"github.com/rasoat/rasoat/internal/deps"
	"github.com/rasoat/rasoat/internal/images"
	"github.com/rasoat/rasoat/internal/rules"
)

// readText reads at most max bytes of a regular file, and only if it is text: a binary file says nothing a pattern should
// read.
func readText(file string, max int64) (string, bool) {
	st, err := os.Stat(file)
	if err != nil || !st.Mode().IsRegular() || st.Size() > max {
		return "", false
	}
	b, err := os.ReadFile(file)
	if err != nil || bytes.IndexByte(b, 0) >= 0 {
		return "", false
	}
	return string(b), true
}

// imageRule applies the user's rule to an image the family table does not know. A family the table cannot judge stays
// listed, not judged, and a note says why.
func imageRule(r images.Ref, ir rules.ImageRule, note func(string)) images.Ref {
	r.Rule = ir.ID()
	if ir.Kind == rules.None {
		r.Acked = true
		return r
	}
	f := images.ByID(ir.Product.Name)
	if f == nil {
		note("rule-family-unknown:" + ir.Product.Name)
		return r
	}
	return images.Reclassify(r, f)
}

// IsManifest says whether the walk reads a file at this path (slash separated, or just a name): a lockfile, a manifest, a
// version pin file, a Dockerfile, a compose file or a CI workflow. The hooks ask it to know when a change is worth a rescan.
func IsManifest(p string) bool {
	slash := filepath.ToSlash(p)
	name, dir := path.Base(slash), path.Dir(slash)
	switch {
	case deps.Reads(name), Manifests[name] != nil, name == "package.json", name == "bun.lockb":
		return true
	case images.IsDockerfile(name), images.IsCompose(name):
		return true
	case images.IsWorkflow(name):
		return path.Base(dir) == "workflows" && path.Base(path.Dir(dir)) == ".github"
	case name == "version.php":
		return path.Base(dir) == "wp-includes"
	}
	return false
}

// RootOf is the directory to walk for a manifest at this path: the project the file belongs to. A workflow belongs to the
// project above .github/workflows, and WordPress's version.php to the directory above wp-includes.
func RootOf(p string) string {
	slash := filepath.ToSlash(p)
	name, dir := path.Base(slash), path.Dir(slash)
	switch {
	case images.IsWorkflow(name) && path.Base(dir) == "workflows" && path.Base(path.Dir(dir)) == ".github":
		return filepath.FromSlash(path.Dir(path.Dir(dir)))
	case name == "version.php" && path.Base(dir) == "wp-includes":
		return filepath.FromSlash(path.Dir(dir))
	}
	return filepath.FromSlash(dir)
}
