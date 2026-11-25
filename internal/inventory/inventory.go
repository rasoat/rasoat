// Package inventory lists every component a directory names, and which data judges each: the walk without the judging.
// A component no data judges is listed all the same: it is what a user's own rules would cover.
package inventory

import (
	"slices"
	"strings"

	"github.com/rasoat/rasoat/internal/deps"
	"github.com/rasoat/rasoat/internal/images"
	"github.com/rasoat/rasoat/internal/osvdb"
	"github.com/rasoat/rasoat/internal/project"
)

// Kinds of component.
const (
	Pin     = "pin"     // a version a file states: a version file, a manifest, a CI pin
	Image   = "image"   // a container image
	Package = "package" // one package a lockfile resolves
)

// What judges a component. A component nothing judges has none (JudgedBy nil).
const (
	Snapshot   = "snapshot"   // the rasoat.com snapshot: Next.js, WordPress, Node.js, PHP, Bun
	Lines      = "lines"      // release lines in the linux index: the image and CI-pin families
	Advisories = "advisories" // an exact tag is judged against the vendor's advisories (nginx, Apache httpd, Caddy, Traefik, Envoy, HAProxy...); a floating tag by release lines
	None       = "none"       // a recognised product no data judges: its name is known, nothing about its versions is (OpenLiteSpeed, LiteSpeed, lighttpd, Tengine)
)

// Item is one component. Version is nil when the file does not name one. Ref is the image or CI pin as the file writes
// it; Unresolved says a variable hides the version, so nothing can be said of it.
type Item struct {
	Kind       string  `json:"kind"`
	Product    string  `json:"product"`
	Version    *string `json:"version"`
	Where      string  `json:"where" untrusted:"4096"`
	JudgedBy   *string `json:"judged_by"`
	Ref        string  `json:"ref,omitempty" untrusted:"1024"`
	Unresolved bool    `json:"unresolved,omitempty"`
	// Rule is the user's rule that read this component. Acknowledged: the user's rule says no data judges it, and that is
	// known: it is not "not judged".
	Rule         string `json:"rule,omitempty"`
	Acknowledged bool   `json:"acknowledged,omitempty"`
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// byRule says which user rule led to the data that judges a component.
func byRule(rule, judge string) *string {
	if rule == "" {
		return ptr(judge)
	}
	return ptr("rule:" + rule + " → " + judge)
}

// judge is what judges a component of a family: its advisories when it has them, else its release lines, else nothing.
func judge(f *images.Family) string {
	switch {
	case f.Advisories:
		return Advisories
	case f.NoEOL:
		return None
	}
	return Lines
}

// Judged: some data judges the component. A recognised product with no data (None) is listed, and is not judged.
func (it Item) Judged() bool {
	return it.JudgedBy != nil && *it.JudgedBy != None && !strings.HasSuffix(*it.JudgedBy, "→ "+None)
}

func imageItem(im project.Image) Item {
	r := im.Ref
	it := Item{Kind: Image, Product: r.Image, Version: ptr(r.Version), Where: im.Path, Ref: r.Raw, Unresolved: r.Unresolved, Rule: r.Rule, Acknowledged: r.Acked}
	if r.Family == nil && !r.Unresolved { // no family reads the tag: it is the tag as written, for a user's own rule
		it.Version = ptr(r.Tag)
	}
	if r.Image == "" { // a CI pin: `node-version: 22`
		it.Kind = Pin
		if r.Family != nil {
			it.Product = r.Family.ID
		}
	}
	if it.Product == "" {
		it.Product = r.Raw
		if r.Name != "" {
			it.Product = r.Name
		}
	}
	switch {
	case r.Unresolved || r.Family == nil:
	case r.Family.Core:
		it.JudgedBy = byRule(r.Rule, Snapshot)
		it.Product = r.Family.ID
	default:
		it.JudgedBy = byRule(r.Rule, judge(r.Family))
		it.Product = r.Family.ID
	}
	return it
}

// Of lists the components of a walked directory: pins, then images, then packages, each by file. The same
// component in the same file is listed once. The next package is a pin (it has its own verdict), not a package.
func Of(w project.Walked) []Item {
	var items []Item
	seen := map[string]bool{}
	add := func(it Item) {
		version := ""
		if it.Version != nil {
			version = *it.Version
		}
		key := strings.Join([]string{it.Kind, it.Product, version, it.Where, it.Ref}, "\x00")
		if !seen[key] {
			seen[key] = true
			items = append(items, it)
		}
	}
	for _, f := range w.Found {
		add(Item{Kind: Pin, Product: f.Product, Version: ptr(f.Version), Where: f.Path, JudgedBy: byRule(f.Rule, Snapshot), Ref: f.Ref, Rule: f.Rule})
	}
	for _, im := range w.Images {
		add(imageItem(im))
	}
	for _, im := range w.Unresolved {
		add(imageItem(im))
	}
	for _, p := range w.Pkgs {
		if p.Eco == deps.NPM && p.Name == "next" {
			continue
		}
		add(Item{Kind: Package, Product: deps.Purl(p.Eco, p.Name), Version: ptr(p.Version), Where: p.File, JudgedBy: byRule(p.Rule, osvdb.File[p.Eco]), Rule: p.Rule})
	}
	slices.SortStableFunc(items, func(a, b Item) int {
		for _, c := range []int{order(a.Kind) - order(b.Kind), strings.Compare(a.Where, b.Where), strings.Compare(a.Product, b.Product)} {
			if c != 0 {
				return c
			}
		}
		return 0
	})
	return items
}

func order(kind string) int {
	switch kind {
	case Pin:
		return 0
	case Image:
		return 1
	}
	return 2
}

// NotJudged are the images and pins no family covers and the references a variable hides, for a scan report. What the
// user's rules acknowledge is not among them.
func NotJudged(w project.Walked) []Item {
	out := []Item{}
	for _, it := range Of(w) {
		if it.Kind != Package && !it.Judged() && !it.Acknowledged {
			out = append(out, it)
		}
	}
	return out
}
