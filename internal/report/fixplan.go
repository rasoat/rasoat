package report

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
)

// The plan is knowledge only: which version, what it asks of the runtime, the command a person or their agent would run.
// Nothing here runs anything.

const topAdvisories = 5

var npmAdd = map[string]string{"package-lock.json": "npm install", "npm-shrinkwrap.json": "npm install", "pnpm-lock.yaml": "pnpm add", "yarn.lock": "yarn add", "bun.lock": "bun add", "package.json": "npm install"}

// A command carries a version from a downloaded file into something an agent may run: only a plain version gets there.
var plainVersion = core.NewRe(`^\d+\.\d+(\.\d+)?(-[0-9A-Za-z.-]+)?$`)
var nodeModules = core.NewRe(`(^|/)node_modules/.*$`)
var exactVersion = core.NewRe(`^\d+\.\d+\.\d+`)

// Change is one place to make the change. Command is nil where there is no one right command; How always says what to do.
type Change struct {
	File    string  `json:"file"`
	Cwd     *string `json:"cwd"`
	Command *string `json:"command"`
	How     string  `json:"how"`
}

type Requirement struct {
	Runtime string  `json:"runtime"`
	Needs   string  `json:"needs"`
	Found   *string `json:"found"` // the version this scan saw, if any
	Met     *bool   `json:"met"`   // nil: this scan saw no exact version
}

type WorstAdvisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
}

type AdvisoryCount struct {
	Total int             `json:"total"`
	Worst []WorstAdvisory `json:"worst"`
}

type Step struct {
	Product      string        `json:"product"`
	Version      *string       `json:"version"`
	Status       string        `json:"status"`
	Action       string        `json:"action"` // upgrade, no-published-fix, cannot-judge
	MoveTo       *string       `json:"move_to"`
	CrossesMajor bool          `json:"crosses_major"`
	Requires     *Requirement  `json:"requires"` // settle this first: the target version does not run on less
	Changes      []Change      `json:"changes"`
	Guides       []string      `json:"guides"`
	Advisories   AdvisoryCount `json:"advisories"`
}

type CleanItem struct {
	Product string  `json:"product"`
	Version *string `json:"version"`
}

type RescanArgs struct {
	Target string `json:"target"`
}

// Rescan is not a shell line: a directory's name is the project's text.
type Rescan struct {
	Tool      string     `json:"tool"`
	Arguments RescanArgs `json:"arguments"`
}

type FixPlan struct {
	Schema     int         `json:"schema"`
	Target     Target      `json:"target"`
	Data       DataInfo    `json:"data"`
	Site       *SiteInfo   `json:"site"`
	Applied    bool        `json:"applied"` // always false: this tool changes nothing
	Steps      []Step      `json:"steps"`
	Clean      []CleanItem `json:"clean"`
	Rescan     Rescan      `json:"rescan"`
	NotChecked []string    `json:"not_checked"`
	Notices    []string    `json:"notices"`
}

// line is the part of a version that makes a move risky: 14 for Next.js and Node.js, 6.4 for WordPress and PHP.
func line(product, v string) string {
	p := strings.Split(v, ".")
	n := 1
	if product == "wordpress" || product == "php" {
		n = 2
	}
	return strings.Join(p[:min(n, len(p))], ".")
}

// guides is the official guide for each major a Next.js move passes through; WordPress has one. Nothing is claimed for the rest.
func guides(product string, from *string, to string) []string {
	out := []string{}
	if product == "wordpress" {
		return []string{"https://wordpress.org/documentation/article/updating-wordpress/"}
	}
	if product != "next" || from == nil {
		return out
	}
	a, _ := strconv.Atoi(strings.Split(*from, ".")[0])
	b, _ := strconv.Atoi(strings.Split(to, ".")[0])
	for m := a + 1; m <= b; m++ {
		if m >= 14 {
			out = append(out, fmt.Sprintf("https://nextjs.org/docs/app/guides/upgrading/version-%d", m))
		}
	}
	return out
}

func change(product, file, to string, isSite bool) Change {
	if isSite {
		return Change{File: file, How: fmt.Sprintf("This address was read from outside. In the project or on the server behind it, move %s to %s.", product, to)}
	}
	name := path.Base(file)
	plain := plainVersion.MatchString(to)
	// A lockfile above the scanned directory: the package that declares the dependency is here, not there. The installed
	// copy in node_modules: the project is above it.
	proj := nodeModules.ReplaceAllString(file, "${1}package.json")
	cwd := path.Dir(proj)
	if strings.HasPrefix(proj, "..") {
		cwd = "."
	}
	cmd := func(c string) *string {
		if plain {
			return &c
		}
		return nil
	}
	switch product {
	case "next":
		add := npmAdd[name]
		if add == "" {
			add = "npm install"
		}
		manager := strings.Fields(add)[0]
		return Change{file, &cwd, cmd(add + " next@" + to), fmt.Sprintf("Move next to %s with %s, in the package that declares it, then commit the lockfile.", to, manager)}
	case "wordpress":
		if name == "composer.lock" {
			return Change{file, &cwd, nil, fmt.Sprintf("Raise the WordPress package in composer.json to %s, then run composer update for it.", to)}
		}
		root := path.Dir(path.Dir(file))
		return Change{file, &root, cmd("wp core update --version=" + to), fmt.Sprintf("Back up the database and files first, then update core to %s (the command needs WP-CLI).", to)}
	}
	return Change{file, &cwd, nil, fmt.Sprintf("Set %s to %s in %s, and install that version wherever the project runs.", product, to, name)}
}

func requirement(r Result, to string, results []Result, l *data.Loaded) *Requirement {
	req := l.Snapshot.Requirements
	runtime, needs, rng := "", "", ""
	switch r.Product {
	case "next":
		runtime = "node"
		for _, n := range req.Next {
			if n.V == to {
				needs = n.Node
				break
			}
		}
		rng = needs
	case "wordpress":
		runtime = "php"
		needs = req.WordPress[line("wordpress", to)]
		rng = ">=" + needs
	}
	if runtime == "" || needs == "" {
		return nil
	}
	var seen *Result
	for i := range results {
		if results[i].Product == runtime {
			seen = &results[i]
			break
		}
	}
	out := &Requirement{Runtime: runtime, Needs: rng}
	if seen != nil && seen.Version != nil {
		out.Found = seen.Version
		if exactVersion.MatchString(*seen.Version) {
			met := core.Satisfies(*seen.Version, rng)
			out.Met = &met
		}
	}
	return out
}

func whyNoMove(r Result) string {
	if r.Status != core.Unknown {
		return "No published release clears every advisory. Read the advisories for a workaround, and watch for a release."
	}
	switch deref(r.Reason) {
	case "version-not-exact":
		return "The version is a range or a partial number. Commit a lockfile or an exact version, then scan again."
	case "version-hidden":
		return "The site does not show its version. Scan the project directory instead."
	}
	return "This version is not in the data, so no verdict is possible. Check it against the project's own release notes."
}

func step(r Result, rep *Report, l *data.Loaded) Step {
	isSite := rep.Target.Kind == "url"
	s := Step{Product: r.Product, Version: r.Version, Status: r.Status, MoveTo: r.Fix, Changes: []Change{}, Guides: []string{}}
	switch {
	case r.Fix != nil:
		s.Action = "upgrade"
		to := *r.Fix
		s.CrossesMajor = r.Version != nil && line(r.Product, to) != line(r.Product, *r.Version)
		s.Requires = requirement(r, to, rep.Results, l)
		for _, f := range r.Sources {
			s.Changes = append(s.Changes, change(r.Product, f, to, isSite))
		}
		s.Guides = guides(r.Product, r.Version, to)
	default:
		s.Action = "no-published-fix"
		if r.Status == core.Unknown {
			s.Action = "cannot-judge"
		}
		for _, f := range r.Sources {
			s.Changes = append(s.Changes, Change{File: f, How: whyNoMove(r)})
		}
	}
	s.Advisories = AdvisoryCount{Total: len(r.Advisories), Worst: []WorstAdvisory{}}
	for i, a := range r.Advisories {
		if i == topAdvisories {
			break
		}
		s.Advisories.Worst = append(s.Advisories.Worst, WorstAdvisory{a.ID, a.Severity, a.URL})
	}
	return s
}

// Plan says what to change for each finding of a report. It applies nothing.
func Plan(rep *Report, l *data.Loaded) *FixPlan {
	p := &FixPlan{Schema: 1, Target: rep.Target, Data: rep.Data, Site: rep.Site, Steps: []Step{}, Clean: []CleanItem{},
		Rescan: Rescan{"scan", RescanArgs{rep.Target.Value}}, NotChecked: rep.NotChecked, Notices: rep.Notices}
	for _, r := range rep.Results {
		if r.Status == core.OK {
			p.Clean = append(p.Clean, CleanItem{r.Product, r.Version})
		} else {
			p.Steps = append(p.Steps, step(r, rep, l))
		}
	}
	return p
}
