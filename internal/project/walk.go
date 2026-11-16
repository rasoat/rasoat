package project

import (
	"github.com/rasoat/rasoat/internal/images"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/deps"
	"github.com/rasoat/rasoat/internal/rules"
)

const (
	maxDepth = 5
	maxDirs  = 20_000
	maxFile  = 64 << 20
)

// Build output, dependencies, and wp-content: plugins ship their own lockfiles, which say nothing about the site.
var skip = map[string]bool{"node_modules": true, "vendor": true, "wp-content": true, "dist": true, "build": true, "out": true, "coverage": true, "tmp": true}

type Found struct {
	Pin
	Path string // relative to the scanned directory, with forward slashes
	Ref  string // the image or CI pin the version came from, when it did not come from a manifest
	Rule string // the user's detector or image rule that read it, when one did
}

// Image is an image or a CI pin of a family judged from release lines, or one that is not judged at all.
type Image struct {
	images.Ref
	Path string
}

type Walked struct {
	Found  []Found
	Images []Image
	Pkgs   []deps.Pkg // every package the lockfiles resolve: npm, crates.io, Go
	// Unresolved are the references a variable hides: also in Notes, as unresolved:<file> (<ref>).
	Unresolved []Image
	Notes      []string // binary-bun-lock, truncated, unresolved:<file> (<ref>)
}

func read(file string) (string, bool) {
	st, err := os.Stat(file)
	if err != nil || st.Size() > maxFile {
		return "", false
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", false // unreadable or absent: says nothing
	}
	return string(b), true
}

func rel(root, file string) string {
	r, err := filepath.Rel(root, file)
	if err != nil {
		return file
	}
	return filepath.ToSlash(r)
}

// lockAbove is the monorepo case: scanning apps/web, whose lockfile is at the repo root. Stops at the repo's top.
func lockAbove(root string) []Found {
	prev := root
	dir := filepath.Dir(root)
	for i := 0; dir != prev && i < 6; i++ {
		for _, name := range nextLocks {
			file := filepath.Join(dir, name)
			if text, ok := read(file); ok {
				var out []Found
				for _, p := range Manifests[name](text) {
					out = append(out, Found{Pin: p, Path: rel(root, file)})
				}
				return out
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return nil
		}
		prev, dir = dir, filepath.Dir(dir)
	}
	return nil
}

// workflows reads the CI pins of the workflow files directly in dir.
func workflows(dir string, addRefs func([]images.Ref, string)) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Type().IsRegular() && images.IsWorkflow(e.Name()) {
			file := filepath.Join(dir, e.Name())
			if text, ok := read(file); ok {
				addRefs(images.Workflow(text), file)
			}
		}
	}
}

// Walk reads a directory's manifests. Text only, follows no symlink, skips what is not the project's own.
func Walk(root string) Walked { return WalkWith(root, nil) }

// WalkWith is Walk with the user's rules: detectors read the files they name, and an image the table does not know is
// what the user says it is. rs is the user's own file, never anything the directory holds.
func WalkWith(root string, rs *rules.Set) Walked {
	var w Walked
	w.Found, w.Images, w.Notes, w.Pkgs, w.Unresolved = []Found{}, []Image{}, []string{}, []deps.Pkg{}, []Image{}
	note := func(n string) {
		if !slices.Contains(w.Notes, n) {
			w.Notes = append(w.Notes, n)
		}
	}
	add := func(ps []Pin, file string) {
		for _, p := range ps {
			w.Found = append(w.Found, Found{Pin: p, Path: rel(root, file)})
		}
	}
	// An image of a runtime the CLI already judges is that runtime's pin; the rest wait for their release lines.
	addRefs := func(refs []images.Ref, file string) {
		for _, r := range refs {
			if r.Family == nil && !r.Unresolved && r.Image != "" {
				if ir, ok := rs.Image(r.Image); ok {
					r = imageRule(r, ir, note)
				}
			}
			switch {
			case r.Unresolved:
				note("unresolved:" + rel(root, file) + " (" + r.Raw + ")")
				w.Unresolved = append(w.Unresolved, Image{r, rel(root, file)})
			case r.Family != nil && r.Family.Core && r.Kind != images.Unpinned:
				w.Found = append(w.Found, Found{Pin{r.Family.ID, r.Version}, rel(root, file), r.Raw, r.Rule})
			default:
				w.Images = append(w.Images, Image{r, rel(root, file)})
			}
		}
	}
	// detect runs one of the user's detectors on a file it names, and files what it finds where the rule says.
	detect := func(d rules.Detector, file string) {
		text, ok := readText(file, rules.MaxDetected)
		if !ok {
			return
		}
		v, ok := d.Detect(text)
		if !ok {
			return
		}
		switch d.Kind {
		case rules.Pkg:
			eco := d.Eco
			if eco == "golang" {
				eco = deps.Go
			}
			if core.ValidVersion(v) {
				w.Pkgs = append(w.Pkgs, deps.Pkg{Eco: eco, Name: d.Product.Name, Version: v, File: rel(root, file), Rule: d.ID()})
			}
		case rules.Family:
			f := images.ByID(d.Product.Name)
			if f == nil {
				note("rule-family-unknown:" + d.Product.Name)
			}
			r := images.Detected(d.ID(), v, f)
			r.Rule = d.ID()
			addRefs([]images.Ref{r}, file)
		default:
			r := images.Detected(d.ID(), v, nil)
			r.Rule, r.Acked = d.ID(), true
			addRefs([]images.Ref{r}, file)
		}
	}
	type ranged struct {
		Found
		dir string
	}
	var ranges []ranged
	var lockDirs []string
	type item struct {
		dir   string
		depth int
	}
	queue := []item{{root, 0}}
	for seen := 0; len(queue) > 0; seen++ {
		if seen >= maxDirs {
			note("truncated")
			break
		}
		it := queue[0]
		queue = queue[1:]
		entries, _ := os.ReadDir(it.dir)
		here := map[string]bool{}
		for _, e := range entries {
			here[e.Name()] = true
		}
		for _, e := range entries {
			name, file := e.Name(), filepath.Join(it.dir, e.Name())
			switch {
			case e.Type().IsRegular():
				for _, d := range rs.For(name) {
					detect(d, file)
				}
				// go.mod only where there is no go.sum: the sum lists what was downloaded, the mod what was asked for.
				if deps.Reads(name) && !(name == "go.mod" && here["go.sum"]) {
					if text, ok := read(file); ok {
						w.Pkgs = append(w.Pkgs, deps.Parse(name, text, rel(root, file))...)
					}
				}
				if images.IsDockerfile(name) || images.IsCompose(name) {
					if text, ok := read(file); ok {
						if images.IsCompose(name) {
							addRefs(images.Compose(text), file)
						} else {
							addRefs(images.Dockerfile(text), file)
						}
					}
				} else if parse := Manifests[name]; parse != nil {
					if text, ok := read(file); ok {
						add(parse(text), file)
					}
					if slices.Contains(nextLocks, name) {
						lockDirs = append(lockDirs, it.dir)
					}
				} else if name == "bun.lockb" {
					note("binary-bun-lock")
				} else if name == "package.json" {
					text, _ := read(file)
					next, ps := Declared(text)
					add(ps, file)
					if next != "" {
						ranges = append(ranges, ranged{Found{Pin: Pin{"next", next}, Path: rel(root, file)}, it.dir})
					}
				}
			case e.IsDir():
				switch {
				case name == "node_modules":
					p := filepath.Join(file, "next", "package.json")
					text, _ := read(p)
					add(InstalledNext(text), p)
				case name == "wp-includes":
					p := filepath.Join(file, "version.php")
					text, _ := read(p)
					add(WpVersionPhp(text), p)
				case name == ".github":
					workflows(filepath.Join(file, "workflows"), addRefs)
				case it.depth < maxDepth && !skip[name] && !strings.HasPrefix(name, "."):
					queue = append(queue, item{file, it.depth + 1})
				}
			}
		}
	}
	// A range is an answer only when no lockfile above or beside it resolved it.
	var open []ranged
	for _, r := range ranges {
		resolved := slices.ContainsFunc(lockDirs, func(d string) bool {
			return r.dir == d || strings.HasPrefix(r.dir, d+string(filepath.Separator))
		})
		if !resolved {
			open = append(open, r)
		}
	}
	var above []Found
	if len(open) > 0 {
		above = lockAbove(root)
	}
	w.Found = append(w.Found, above...)
	if len(above) == 0 {
		for _, r := range open {
			w.Found = append(w.Found, r.Found)
		}
	}
	return w
}
