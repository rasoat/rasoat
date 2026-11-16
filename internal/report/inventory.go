package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/images"
	"github.com/rasoat/rasoat/internal/inventory"
	"github.com/rasoat/rasoat/internal/project"
)

// InventorySummary counts the components. Packages are counted per ecosystem (npm, cargo, golang), listed or not.
type InventorySummary struct {
	Components int `json:"components"`
	Judged     int `json:"judged"`
	NotJudged  int `json:"not_judged"`
	// Acknowledged are the components the user's rules say no data judges: known, so not "not judged".
	Acknowledged int            `json:"acknowledged"`
	Packages     map[string]int `json:"packages"`
}

// Inventory is the document `rasoat discover --json` prints: what a directory names, and which data judges each part.
// Nothing here is a verdict.
type Inventory struct {
	Schema  int              `json:"schema"`
	Kind    string           `json:"kind"`
	Tool    Tool_            `json:"tool"`
	Target  Target           `json:"target"`
	Summary InventorySummary `json:"summary"`
	Items   []inventory.Item `json:"items"`
	Notes   []string         `json:"notes"`
	Notices []string         `json:"notices"`
}

// InventoryOf is the inventory of a walked directory. withPackages: list every lockfile package; without, they are
// counted only (a monorepo has thousands, and an agent's context is not for them).
func InventoryOf(root string, w project.Walked, withPackages bool) *Inventory {
	all := inventory.Of(w)
	inv := &Inventory{Schema: 1, Kind: "inventory", Tool: Tool_{Tool, Version}, Target: Target{"dir", root}, Items: []inventory.Item{}, Notes: w.Notes, Notices: core.NOTICES}
	inv.Summary.Packages = map[string]int{}
	for _, it := range all {
		inv.Summary.Components++
		if it.Acknowledged {
			inv.Summary.Acknowledged++
		} else if it.JudgedBy == nil {
			inv.Summary.NotJudged++
		} else {
			inv.Summary.Judged++
		}
		if it.Kind == inventory.Package {
			eco, _, _ := strings.Cut(strings.TrimPrefix(it.Product, "pkg:"), "/")
			inv.Summary.Packages[eco]++
			if !withPackages {
				continue
			}
		}
		inv.Items = append(inv.Items, it)
	}
	return inv
}

func judgedBy(it inventory.Item, t text) string {
	if it.Acknowledged {
		return fmt.Sprintf(t.acknowledged, it.Rule)
	}
	if it.JudgedBy == nil {
		return t.notJudgedBy
	}
	return *it.JudgedBy
}

// RenderInventory is the terminal view of an inventory. Lockfile packages are counted per ecosystem, not listed.
func RenderInventory(inv *Inventory, lang string) string {
	t := texts[lang]
	out := []string{fmt.Sprintf("%s %s: %s %s", inv.Tool.Name, inv.Tool.Version, t.discovered, inv.Target.Value), ""}
	listed := 0
	for _, it := range inv.Items {
		if it.Kind == inventory.Package {
			continue
		}
		listed++
		name := core.ProductNames[it.Product]
		if name == "" {
			name = images.Name(it.Product)
		}
		version := ""
		if it.Version != nil {
			version = " " + *it.Version
		}
		where := it.Where
		if it.Ref != "" {
			where += " (" + it.Ref + ")"
		}
		out = append(out, pad(it.Kind, 6)+" "+name+version+"  "+where+"  ["+judgedBy(it, t)+"]")
	}
	ecos := make([]string, 0, len(inv.Summary.Packages))
	for e := range inv.Summary.Packages {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		out = append(out, fmt.Sprintf(t.discPackages, e, inv.Summary.Packages[e]))
	}
	if listed == 0 && len(ecos) == 0 {
		out = append(out, t.discNothing)
	}
	for _, n := range inv.Notes {
		if v, ok := strings.CutPrefix(n, "unresolved:"); ok {
			out = append(out, fmt.Sprintf(t.unresolved, v))
		} else if v, ok := strings.CutPrefix(n, "rule-family-unknown:"); ok {
			out = append(out, fmt.Sprintf(t.ruleFamily, v))
		} else if s, ok := t.notes[n]; ok {
			out = append(out, s)
		} else {
			out = append(out, n)
		}
	}
	summary := fmt.Sprintf(t.discSummary, inv.Summary.Components, inv.Summary.Judged, inv.Summary.NotJudged)
	if inv.Summary.Acknowledged > 0 {
		summary += fmt.Sprintf(t.discAcked, inv.Summary.Acknowledged)
	}
	out = append(out, "", summary)
	out = append(out, inv.Notices...)
	return controls.ReplaceAllString(strings.Join(out, "\n"), "")
}
