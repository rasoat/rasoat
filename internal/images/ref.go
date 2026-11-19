package images

import (
	"strings"

	"github.com/rasoat/rasoat/internal/core"
)

// Kind says how much a tag pins.
type Kind int

const (
	Exact    Kind = iota // names one release: 16.4, 1.4.4, 1.24.0-alpine3.19
	Line                 // names a line that moves: 16, 7-alpine, 3.12, bookworm
	Unpinned             // latest, stable, no tag, a digest only: says nothing
)

// Ref is one image or CI pin as a file writes it.
type Ref struct {
	Raw        string  // what the file says, after literal ARG and ${X:-default} substitution
	Image      string  // the name without registry; empty for a CI pin
	Family     *Family // nil: not in the table, listed and not judged
	Kind       Kind
	Version    string // the release or line the tag names; empty when Unpinned
	Tag        string
	Unresolved bool // a variable with no literal value: nothing can be said
	// Set by the user's rules: Rule is the rule that read this reference, Acked says the user knows it and no data judges it,
	// Name is the product a detector found when the family table has no such id.
	Rule  string
	Acked bool
	Name  string
}

var (
	tagRe = core.NewRe(`^v?(\d+(?:\.\d+)*)(?:[-_](.+))?$`)
	pgRe  = core.NewRe(`(?:^|[-_])pg(\d+)(?:$|[-_.])`)
)

// Split cuts `registry/ns/name:tag@digest` into the name without registry and the tag.
func Split(ref string) (image, tag string) {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref, tag = ref[:i], ref[i+1:]
	}
	parts := strings.Split(ref, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		parts = parts[1:] // a registry host
	}
	if len(parts) > 1 && parts[0] == "library" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/"), tag
}

// ParseRef reads one image reference.
func ParseRef(raw string) Ref {
	if strings.Contains(raw, "$") {
		return Ref{Raw: raw, Unresolved: true}
	}
	image, tag := Split(raw)
	r := Ref{Raw: raw, Image: image, Tag: tag, Family: lookup(image)}
	if r.Family != nil {
		r.Kind, r.Version = classify(r.Family, tag)
	}
	return r
}

// FromPin reads a CI runtime pin, `node-version: 22`, whose value follows the same rules as a tag.
func FromPin(key, value string) Ref {
	raw := key + "-version: " + value
	if strings.Contains(value, "$") {
		return Ref{Raw: raw, Unresolved: true}
	}
	f := byID[ciKeys[key]]
	v := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(value, "v"), ".x"), ".*")
	r := Ref{Raw: raw, Family: f, Tag: value}
	r.Kind, r.Version = classify(f, v)
	return r
}

func classify(f *Family, tag string) (Kind, string) {
	if tag == "" {
		return Unpinned, ""
	}
	if f.PgTag {
		if m := pgRe.FindStringSubmatch(tag); m != nil {
			return Line, m[1]
		}
		return Unpinned, ""
	}
	tag = withoutPrefixes(f, tag)
	if f.Codenames != nil {
		name, _, _ := strings.Cut(tag, "-")
		if cycle := f.Codenames[name]; cycle != "" {
			return Line, cycle
		}
	}
	m := tagRe.FindStringSubmatch(tag)
	if m == nil {
		return Unpinned, ""
	}
	if f.Distro || len(strings.Split(m[1], ".")) < f.ExactParts {
		return Line, m[1]
	}
	return Exact, m[1]
}

// withoutPrefixes reads past the flavour words a family's tags put before the version: `contrib-distroless-v1.36.2`.
func withoutPrefixes(f *Family, tag string) string {
	for cut := len(f.Prefixes) > 0; cut; {
		cut = false
		for _, p := range f.Prefixes {
			if rest, ok := strings.CutPrefix(tag, p+"-"); ok {
				tag, cut = rest, true
			}
		}
	}
	return tag
}

// Reclassify reads the tag of an image the table did not know as a member of family f: the user's rule says so.
func Reclassify(r Ref, f *Family) Ref {
	r.Family = f
	r.Kind, r.Version = classify(f, r.Tag)
	return r
}

// Detected is a version a user's detector found, as a pin of family f, or of no family the table knows (f nil: it is
// listed, and no data judges it).
func Detected(name, version string, f *Family) Ref {
	r := Ref{Raw: name + ": " + version, Family: f, Tag: version, Name: name}
	if f != nil {
		r.Kind, r.Version = classify(f, version)
	}
	return r
}
