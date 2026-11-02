package core_test

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
)

type contract struct {
	Today     string  `json:"today"`
	Rows      [][]any `json:"rows"`
	Satisfies [][]any `json:"satisfies"`
	Orders    [][]any `json:"orders"`
}

// The file is what the web app's TypeScript core answers (scripts/cli/conformance.ts). The two must not drift.
func load(t *testing.T) (out contract) {
	f, err := os.Open("testdata/conformance.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(z).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func str(v any) *string {
	if v == nil {
		return nil
	}
	s := v.(string)
	return &s
}

func same(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func show(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestVerdictsEqualTheTypeScriptCore(t *testing.T) {
	c := load(t)
	snap := data.Bundled()
	bad := 0
	for _, r := range c.Rows {
		product := r[0].(string)
		v := core.VerdictFor(product, str(r[1]), snap, c.Today)
		ids := []string{}
		for _, a := range v.Advisories {
			ids = append(ids, a.ID)
		}
		want := []string{}
		for _, id := range r[7].([]any) {
			want = append(want, id.(string))
		}
		if !same(v.Version, str(r[2])) || v.Status != r[3].(string) || !same(v.Fix, str(r[4])) || v.NoFix != r[5].(bool) || !same(v.Reason, str(r[6])) || !slices.Equal(ids, want) {
			bad++
			if bad <= 25 {
				t.Errorf("%s %q: got %s %s fix=%s noFix=%v reason=%s n=%d; want %v %v fix=%v noFix=%v reason=%v n=%d", product, show(str(r[1])), show(v.Version), v.Status, show(v.Fix), v.NoFix, show(v.Reason), len(ids), r[2], r[3], r[4], r[5], r[6], len(want))
			}
		}
	}
	t.Logf("%d verdicts, %d differ", len(c.Rows), bad)
}

func TestRangesAndOrderEqualBunSemver(t *testing.T) {
	c := load(t)
	bad := 0
	for _, r := range c.Satisfies {
		if got := core.Satisfies(r[0].(string), r[1].(string)); got != r[2].(bool) {
			bad++
			if bad <= 20 {
				t.Errorf("satisfies(%v, %v) = %v", r[0], r[1], got)
			}
		}
	}
	for _, r := range c.Orders {
		if got := core.Order(r[0].(string), r[1].(string)); float64(got) != r[2].(float64) {
			bad++
			if bad <= 20 {
				t.Errorf("order(%v, %v) = %v, want %v", r[0], r[1], got, r[2])
			}
		}
	}
	t.Logf("%d ranges, %d orders, %d differ", len(c.Satisfies), len(c.Orders), bad)
}
