package core_test

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
)

// The shared verdict: the TypeScript serverVerdict's answer for every bound of every product's list and the versions around it,
// all versions against every product (scripts/cli/conformance.ts).
func TestServerVerdictsEqualTheTypeScriptCore(t *testing.T) {
	c := load(t)
	if len(c.Servers) < 400 {
		t.Fatalf("only %d server rows: regenerate with scripts/cli/conformance.ts", len(c.Servers))
	}
	snap := data.Bundled()
	bad, refused, products := 0, 0, map[string]bool{}
	for _, r := range c.Servers {
		product, version, status := r[0].(string), r[1].(string), r[2].(string)
		products[product] = true
		d := snap.Servers[product]
		if d == nil {
			t.Fatalf("the built-in snapshot has no %s list", product)
		}
		got, ok := core.ServerVerdict(version, d)
		if status == "refused" {
			refused++
			if ok {
				bad++
				t.Errorf("%s %q: the TypeScript core refuses it, this one judged it %s", product, version, got.Status)
			}
			continue
		}
		want := []string{}
		for _, h := range r[4].([]any) {
			want = append(want, h.([]any)[0].(string)+" "+h.([]any)[1].(string))
		}
		have := []string{}
		for _, h := range got.Hits {
			have = append(have, h.ID+" "+h.Severity)
		}
		fix := ""
		if r[3] != nil {
			fix = r[3].(string)
		}
		if !ok || got.Status != status || got.Fix != fix || !slices.Equal(have, want) || got.Line != r[5].(string) || got.EOL != r[6].(bool) {
			bad++
			if bad <= 25 {
				t.Errorf("%s %q: got %s fix=%q line=%s eol=%v %v; want %s fix=%q line=%v eol=%v %v", product, version, got.Status, got.Fix, got.Line, got.EOL, have, status, fix, r[5], r[6], want)
			}
		}
	}
	if len(products) < 2 {
		t.Errorf("rows for %v: both products are meant to be covered", products)
	}
	t.Logf("%d server verdicts (%d refused), %d differ", len(c.Servers), refused, bad)
}

// The pinned cases of the plan, against the built-in data: not only agreement with TypeScript but the right answers.
func TestServerPlanCases(t *testing.T) {
	n, h := data.Bundled().Servers["nginx"], data.Bundled().Servers["apache-http-server"]
	for _, c := range []struct {
		d                    *core.ServerAdvisories
		version, status, fix string
	}{
		{n, "1.31.8", core.Vulnerable, cleanNginx(t, "1.31")}, {n, "1.30.6", core.Vulnerable, cleanNginx(t, "1.30")}, {n, cleanNginx(t, "1.31"), core.OK, ""}, {n, cleanNginx(t, "1.30"), core.OK, ""},
		{h, "2.4.70", core.Vulnerable, "2.4.71"}, {h, "2.4.71", core.OK, ""}, {h, "2.2.34", core.Vulnerable, "2.4.71"},
	} {
		got, ok := core.ServerVerdict(c.version, c.d)
		if !ok || got.Status != c.status || got.Fix != c.fix {
			t.Errorf("%s %s: %+v", c.d.Product, c.version, got)
		}
	}
	got, _ := core.ServerVerdict("1.31.8", n)
	if !slices.ContainsFunc(got.Hits, func(x core.ServerHit) bool { return x.ID == "CVE-2026-123007" && x.Severity == "high" }) || !slices.ContainsFunc(got.Hits, func(x core.ServerHit) bool { return x.ID == "CVE-2026-123633" }) {
		t.Errorf("%+v", got.Hits)
	}
	if got, _ := core.ServerVerdict("2.2.34", h); !got.EOL || got.Line != "2.2" {
		t.Errorf("2.2.34: %+v", got)
	}
	for _, v := range []string{"alpine", "1.31", "latest", "", "1.2.3.4", "v1.31.8", "1.32.0"} {
		if _, ok := core.ServerVerdict(v, n); ok {
			t.Errorf("%q is not judged: not exact, or a line the data does not name", v)
		}
	}
	if _, ok := core.ServerVerdict("2.6.0", h); ok {
		t.Error("2.6.0 is on a line the data does not name")
	}
}

// cleanNginx is the lowest release of a line that the snapshot's own verdict clears of every advisory: the releases named
// as fixes in the data, tried from the lowest up. It is the data's answer, so a new advisory moves it.
func cleanNginx(t *testing.T, line string) string {
	t.Helper()
	d := data.Bundled().Servers["nginx"]
	var cands []string
	for _, a := range d.Advisories {
		for _, f := range a.Fixed {
			if strings.HasPrefix(f, line+".") && !slices.Contains(cands, f) {
				cands = append(cands, f)
			}
		}
	}
	num := func(v string) []int {
		var out []int
		for _, p := range strings.Split(v, ".") {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	slices.SortFunc(cands, func(a, b string) int { return slices.Compare(num(a), num(b)) })
	for _, c := range cands {
		if r, ok := core.ServerVerdict(c, d); ok && r.Status == core.OK {
			return c
		}
	}
	t.Fatalf("no release of nginx %s is clear of every advisory in the snapshot (fixes named: %v)", line, cands)
	return ""
}

func TestServerRulesOnAMadeUpProduct(t *testing.T) {
	adv := func(id, vulnerable string, fixed ...string) core.ServerAdvisory {
		return core.ServerAdvisory{ID: id, Severity: "low", URL: "https://example.com/" + id, Vulnerable: []string{vulnerable}, Fixed: append([]string{}, fixed...)}
	}
	list := func(parts int, line string, a ...core.ServerAdvisory) *core.ServerAdvisories {
		return &core.ServerAdvisories{Product: "x", Source: "https://example.com/", LineParts: parts, Lines: []core.ServerLine{{Line: line}}, Fetched: "2026-11-19", Advisories: a}
	}
	d := list(2, "1.0", adv("A", "1.0.30-<1.0.66", "1.0.66"), adv("B", "1.0.0-1.0.99"), adv("N", "all"))
	d.Advisories[1].Severity, d.Advisories[2].Severity = "none", "none"
	if r, _ := core.ServerVerdict("1.0.65", d); r.Status != core.Vulnerable || len(r.Hits) != 1 || r.Fix != "1.0.66" {
		t.Errorf("1.0.65: %+v", r)
	}
	if r, _ := core.ServerVerdict("1.0.66", d); r.Status != core.OK {
		t.Errorf("1.0.66: %+v", r)
	}
	// An advisory that starts above the version still reaches the first fix: the fix moves on.
	d = list(2, "1.0", adv("A", "1.0.0", "1.0.1"), adv("B", "1.0.1", "1.0.2"))
	if r, _ := core.ServerVerdict("1.0.0", d); len(r.Hits) != 1 || r.Fix != "1.0.2" {
		t.Errorf("moving fix: %+v", r)
	}
	// lineParts: three numbers name a line, an exact version has four.
	d = list(3, "1.0.0", adv("A", "1.0.0.0-1.0.0.4", "1.0.0.5"))
	if r, ok := core.ServerVerdict("1.0.0.4", d); !ok || r.Fix != "1.0.0.5" || r.Line != "1.0.0" {
		t.Errorf("four numbers: %+v", r)
	}
	if _, ok := core.ServerVerdict("1.0.0", d); ok {
		t.Error("three numbers is not an exact version of this product")
	}
}

// A snapshot from before the field existed still loads (no server is then judged); one list that does not read is dropped
// alone, the other and the rest of the snapshot stay.
func TestSnapshotsWithoutOrWithBrokenServersStillLoad(t *testing.T) {
	var raw map[string]any
	b, err := json.Marshal(data.Bundled())
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &raw)
	nginx := raw["servers"].(map[string]any)["nginx"]
	line := []any{map[string]any{"line": "2.4", "eol": false}}
	list := func(advisory map[string]any) map[string]any {
		return map[string]any{"product": "apache-http-server", "source": "https://x.example/", "lineParts": 2, "lines": line, "fetched": "2026-11-19", "advisories": []any{advisory}}
	}
	adv := func(vulnerable, fixed string, severity string) map[string]any {
		return map[string]any{"id": "X", "title": "t", "severity": severity, "url": "https://x.example/x", "vulnerable": []string{vulnerable}, "fixed": []string{fixed}}
	}
	for name, servers := range map[string]any{
		"absent":            nil,
		"range":             map[string]any{"apache-http-server": list(adv("2.4.0-x", "2.4.1", "low"))},
		"fix off the lines": map[string]any{"apache-http-server": list(adv("2.4.0", "2.9.1", "low"))},
		"severity":          map[string]any{"apache-http-server": list(adv("2.4.0", "2.4.1", "important"))},
		"wrong key":         map[string]any{"httpd": list(adv("2.4.0", "2.4.1", "low"))},
	} {
		keep := map[string]any{"nginx": nginx}
		if servers != nil {
			for k, v := range servers.(map[string]any) {
				keep[k] = v
			}
		}
		raw["servers"] = keep
		if servers == nil {
			delete(raw, "servers")
		}
		body, _ := json.Marshal(raw)
		s := core.ParseSnapshot(body)
		if s == nil {
			t.Errorf("%s: the snapshot did not load", name)
			continue
		}
		if s.Servers["apache-http-server"] != nil || s.Servers["httpd"] != nil {
			t.Errorf("%s: the bad list was kept", name)
		}
		if _, has := s.Counts()["server:apache-http-server"]; has {
			t.Errorf("%s: a dropped list is still counted", name)
		}
		if servers != nil && s.Servers["nginx"] == nil {
			t.Errorf("%s: the good list was dropped with the bad one", name)
		}
	}
}

func TestCountsHaveOneEntryPerProduct(t *testing.T) {
	c := data.Bundled().Counts()
	for _, k := range []string{"next", "wordpress", "node", "php", "bun", "server:nginx", "server:apache-http-server"} {
		if c[k] == 0 {
			t.Errorf("%s: no records counted (%v)", k, c)
		}
	}
	if floor := map[string]int{"server:nginx": 100, "server:squid": 10}; core.KeepsCoverage(map[string]int{"server:nginx": 100}, floor) {
		t.Error("a product that vanished kept the coverage")
	}
	if !core.KeepsCoverage(map[string]int{"server:nginx": 95, "server:new": 3}, map[string]int{"server:nginx": 100}) {
		t.Error("a new product or a small drop broke the coverage")
	}
}

// A listed issue with no published severity is a hit: only `none` is left out.
func TestServerUnknownSeverityIsAHit(t *testing.T) {
	d := &core.ServerAdvisories{Product: "x", Source: "https://example.com/", LineParts: 2, Lines: []core.ServerLine{{Line: "1.0"}}, Fetched: "2026-11-19",
		Advisories: []core.ServerAdvisory{{ID: "U", Severity: "unknown", URL: "https://example.com/U", Vulnerable: []string{"1.0.0-<1.0.5"}, Fixed: []string{"1.0.5"}}}}
	r, ok := core.ServerVerdict("1.0.1", d)
	if !ok || r.Status != core.Vulnerable || len(r.Hits) != 1 || r.Hits[0].Severity != "unknown" || r.Fix != "1.0.5" {
		t.Errorf("1.0.1: %+v %v", r, ok)
	}
}
