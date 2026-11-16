package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rasoat/rasoat/internal/inventory"
	"github.com/rasoat/rasoat/internal/project"
	"github.com/rasoat/rasoat/internal/report"
	"github.com/rasoat/rasoat/internal/rules"
)

// ruleCheck is one rule and what it matches in the directory.
type ruleCheck struct {
	Rule    string           `json:"rule"`
	Says    string           `json:"says"`
	Matches []inventory.Item `json:"matches"`
}

type rulesCheck struct {
	Schema int          `json:"schema"`
	Kind   string       `json:"kind"`
	Tool   report.Tool_ `json:"tool"`
	Rules  *string      `json:"rules_file"`
	Target string       `json:"target"`
	Checks []ruleCheck  `json:"checks"`
}

const maxShown = 5

// rulesCommand is `rasoat rules check [dir]`: validate the user's rules file and show what each rule matches in a
// directory. Offline: it walks files and nothing more.
func rulesCommand(o options) int {
	target := "."
	if len(o.positionals) == 3 {
		target = o.positionals[2]
	}
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		fmt.Fprintln(os.Stderr, "Not a directory: "+target)
		return 2
	}
	dir, _ := filepath.Abs(target)
	rs, err := rules.Load(o.rules)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	doc := rulesCheck{Schema: 1, Kind: "rules_check", Tool: report.Tool_{Name: report.Tool, Version: report.Version}, Target: dir, Checks: []ruleCheck{}}
	if rs == nil {
		if o.json {
			fmt.Println(report.JSON(doc))
		} else {
			fmt.Printf("No rules file at %s. Nothing to check.\n", rules.DefaultPath())
		}
		return 0
	}
	doc.Rules = &rs.Path
	items := inventory.Of(project.WalkWith(dir, rs))
	add := func(id, says string) {
		c := ruleCheck{Rule: id, Says: says, Matches: []inventory.Item{}}
		for _, it := range items {
			if it.Rule == id {
				c.Matches = append(c.Matches, it)
			}
		}
		doc.Checks = append(doc.Checks, c)
	}
	for _, r := range rs.Images {
		add(r.ID(), r.Product.String())
	}
	for _, d := range rs.Detectors {
		add(d.ID(), d.Product.String())
	}
	if o.json {
		fmt.Println(report.JSON(doc))
		return 0
	}
	out := []string{fmt.Sprintf("rasoat rules: %s: %d image rules, %d detectors, valid", rs.Path, len(rs.Images), len(rs.Detectors)), "read " + dir}
	for _, c := range doc.Checks {
		out = append(out, "", c.Rule+" -> "+c.Says)
		if len(c.Matches) == 0 {
			out = append(out, "  no match here")
		}
		for i, m := range c.Matches {
			if i == maxShown {
				out = append(out, fmt.Sprintf("  +%d more", len(c.Matches)-maxShown))
				break
			}
			version := ""
			if m.Version != nil {
				version = " " + *m.Version
			}
			judge := "not judged by any data"
			switch {
			case m.Acknowledged:
				judge = "known, no data judges it"
			case m.JudgedBy != nil:
				judge = *m.JudgedBy
			}
			out = append(out, "  "+m.Kind+" "+m.Product+version+"  "+m.Where+"  ["+judge+"]")
		}
	}
	fmt.Println(report.Clean(strings.Join(out, "\n")))
	return 0
}
