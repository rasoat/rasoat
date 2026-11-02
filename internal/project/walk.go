package project

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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
}

type Walked struct {
	Found []Found
	Notes []string // binary-bun-lock, truncated
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
					out = append(out, Found{p, rel(root, file)})
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

// Walk reads a directory's manifests. Text only, follows no symlink, skips what is not the project's own.
func Walk(root string) Walked {
	var w Walked
	w.Found, w.Notes = []Found{}, []string{}
	note := func(n string) {
		if !slices.Contains(w.Notes, n) {
			w.Notes = append(w.Notes, n)
		}
	}
	add := func(ps []Pin, file string) {
		for _, p := range ps {
			w.Found = append(w.Found, Found{p, rel(root, file)})
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
		for _, e := range entries {
			name, file := e.Name(), filepath.Join(it.dir, e.Name())
			switch {
			case e.Type().IsRegular():
				if parse := Manifests[name]; parse != nil {
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
						ranges = append(ranges, ranged{Found{Pin{"next", next}, rel(root, file)}, it.dir})
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
