// Package rules is the user's own detectors: a file of rules that tells discover and scan what a name or a file means to
// this user. It is read from the user's config, never from a scanned directory: a repository you scan must not change how
// it is judged. Text only; the patterns are RE2, so no pattern can run away.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/rasoat/rasoat/internal/images"
)

const (
	version  = 1
	maxFile  = 256 << 10
	maxRules = 200
)

// MaxDetected is the most a detector reads of one file.
const MaxDetected = 1 << 20

// Kinds of what a rule says a thing is.
const (
	None   = "none"   // known, and judged by nothing: the inventory lists it, and it leaves not judged
	Family = "family" // judged by release lines
	Pkg    = "pkg"    // judged as a package of an ecosystem
)

// Product is the right side of a rule. Eco is npm, cargo or golang; Name is the family id or the package name.
type Product struct {
	Kind, Eco, Name string
}

func (p Product) String() string {
	switch p.Kind {
	case Family:
		return "family:" + p.Name
	case Pkg:
		return "pkg:" + p.Eco + "/" + p.Name
	}
	return None
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9._~@/-]{0,213}$`)
	imageRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
)

// ParseProduct reads `family:<id>`, `pkg:<eco>/<name>` or `none`.
func ParseProduct(s string) (Product, error) {
	switch {
	case s == None:
		return Product{Kind: None}, nil
	case strings.HasPrefix(s, "family:"):
		id := strings.TrimPrefix(s, "family:")
		if !idRe.MatchString(id) {
			return Product{}, fmt.Errorf("%q: a family id is lower case letters, digits, '.', '_' or '-'", s)
		}
		return Product{Kind: Family, Name: id}, nil
	case strings.HasPrefix(s, "pkg:"):
		eco, name, ok := strings.Cut(strings.TrimPrefix(s, "pkg:"), "/")
		if !ok || (eco != "npm" && eco != "cargo" && eco != "golang") || !nameRe.MatchString(name) {
			return Product{}, fmt.Errorf("%q: a package is pkg:npm/<name>, pkg:cargo/<name> or pkg:golang/<module>", s)
		}
		return Product{Kind: Pkg, Eco: eco, Name: name}, nil
	}
	return Product{}, fmt.Errorf("%q: say family:<id>, pkg:<eco>/<name> or none", s)
}

// ImageRule says what an image the built-in table does not know is.
type ImageRule struct {
	Image string
	Product
}

// ID is how a report names the rule.
func (r ImageRule) ID() string { return "image:" + r.Image }

// Detector reads a version out of the files whose names match.
type Detector struct {
	Name  string
	Files []string
	Re    *regexp.Regexp
	Product
}

// ID is how a report names the rule.
func (d Detector) ID() string { return d.Name }

// Detect returns the capture of the first line the pattern matches, if it is a plain version.
func (d Detector) Detect(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		if m := d.Re.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil && versionRe.MatchString(m[1]) {
			return m[1], true
		}
	}
	return "", false
}

// Set is a loaded rules file. A nil *Set has no rules.
type Set struct {
	Path      string
	Images    []ImageRule
	Detectors []Detector
}

// Image is the rule for an image name without registry, if there is one.
func (s *Set) Image(name string) (ImageRule, bool) {
	if s != nil {
		for _, r := range s.Images {
			if r.Image == name {
				return r, true
			}
		}
	}
	return ImageRule{}, false
}

// For lists the detectors that read a file of this name.
func (s *Set) For(base string) []Detector {
	var out []Detector
	if s != nil {
		for _, d := range s.Detectors {
			for _, g := range d.Files {
				if ok, _ := path.Match(g, base); ok {
					out = append(out, d)
					break
				}
			}
		}
	}
	return out
}

// DefaultPath is $XDG_CONFIG_HOME/rasoat/rules.json or ~/.config/rasoat/rules.json.
func DefaultPath() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "rasoat", "rules.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "rasoat", "rules.json")
}

// Load reads the rules file at file; "" is the default path, where a missing file is no rules (nil). A file the user
// named that is missing is an error.
func Load(file string) (*Set, error) {
	explicit := file != ""
	if !explicit {
		if file = DefaultPath(); file == "" {
			return nil, nil
		}
	}
	st, err := os.Stat(file)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("rules: cannot read %s", file)
	}
	if !st.Mode().IsRegular() || st.Size() > maxFile {
		return nil, fmt.Errorf("rules: %s is not a regular file under %d KB", file, maxFile>>10)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("rules: cannot read %s", file)
	}
	return Parse(b, file)
}

type rawFile struct {
	Version   *int              `json:"version"`
	Images    map[string]string `json:"images"`
	Detectors []rawDetector     `json:"detectors"`
}

type rawDetector struct {
	Name    string   `json:"name"`
	Files   []string `json:"files"`
	Regex   string   `json:"regex"`
	Product string   `json:"product"`
}

// Parse validates a rules file. Unknown keys, a wrong version and a bad rule are errors that say which.
func Parse(b []byte, file string) (*Set, error) {
	fail := func(format string, a ...any) (*Set, error) {
		return nil, fmt.Errorf("rules: %s: %s", file, fmt.Sprintf(format, a...))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var raw rawFile
	if err := dec.Decode(&raw); err != nil {
		return fail("%v", err)
	}
	if dec.More() {
		return fail("more than one JSON value")
	}
	if raw.Version == nil || *raw.Version != version {
		return fail(`"version" must be %d`, version)
	}
	if len(raw.Images)+len(raw.Detectors) > maxRules {
		return fail("more than %d rules", maxRules)
	}
	s := &Set{Path: file}
	names := make([]string, 0, len(raw.Images))
	for k := range raw.Images {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		p, err := ParseProduct(raw.Images[k])
		if err != nil || p.Kind == Pkg {
			return fail(`images[%q]: say family:<id> or none`, k)
		}
		name, _ := images.Split(k) // a reference is matched as the files are read: no registry, no tag
		if !imageRe.MatchString(name) {
			return fail("images[%q]: not an image name (lower case, no registry needed)", k)
		}
		s.Images = append(s.Images, ImageRule{Image: name, Product: p})
	}
	seen := map[string]bool{}
	for i, d := range raw.Detectors {
		at := fmt.Sprintf("detectors[%d]", i)
		if !idRe.MatchString(d.Name) {
			return fail(`%s: "name" is lower case letters, digits, '.', '_' or '-'`, at)
		}
		at = fmt.Sprintf("detectors[%q]", d.Name)
		if seen[d.Name] {
			return fail("%s: the name is used twice", at)
		}
		seen[d.Name] = true
		if len(d.Files) == 0 {
			return fail(`%s: "files" needs at least one file name or glob`, at)
		}
		for _, g := range d.Files {
			if g == "" || strings.ContainsAny(g, `/\`) {
				return fail("%s: %q is matched on a file's name, so it has no '/'", at, g)
			}
			if _, err := path.Match(g, "x"); err != nil {
				return fail("%s: %q is not a glob", at, g)
			}
		}
		re, err := regexp.Compile(d.Regex)
		if err != nil {
			return fail("%s: regex: %v", at, err)
		}
		if re.NumSubexp() != 1 {
			return fail("%s: regex needs exactly one capture group, it has %d", at, re.NumSubexp())
		}
		p, err := ParseProduct(d.Product)
		if err != nil {
			return fail("%s: product %v", at, err)
		}
		s.Detectors = append(s.Detectors, Detector{Name: d.Name, Files: d.Files, Re: re, Product: p})
	}
	return s, nil
}
