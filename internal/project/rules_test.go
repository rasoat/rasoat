package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/rules"
)

// A detector reads text the walk meets, under the walk's own limits: not a symlink, not a binary, not a huge file, not
// what the walk skips.
func TestADetectorReadsOnlyTextTheWalkMeets(t *testing.T) {
	rs, err := rules.Parse([]byte(`{"version":1,"detectors":[{"name":"v","files":["VERSION"],"regex":"^(\\d+\\.\\d+\\.\\d+)$","product":"pkg:npm/lodash"}]}`), "f")
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	put := func(rel, text string) {
		f := filepath.Join(d, rel)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("VERSION", "1.0.0\n")
	put("sub/VERSION", "\x00\x00 binary\n1.0.1\n")
	put("big/VERSION", strings.Repeat("x\n", rules.MaxDetected)+"1.0.2\n")
	put("node_modules/p/VERSION", "1.0.3\n")
	put("real/VERSION", "1.0.4\n")
	if err := os.Symlink(filepath.Join(d, "real", "VERSION"), filepath.Join(d, "link-VERSION")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(d, "real", "VERSION"), filepath.Join(d, "linked", "VERSION")); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range WalkWith(d, rs).Pkgs {
		got = append(got, p.File+"="+p.Version+" via "+p.Rule)
	}
	if strings.Join(got, ",") != "VERSION=1.0.0 via v,real/VERSION=1.0.4 via v" {
		t.Errorf("%v", got)
	}
	if n := len(Walk(d).Pkgs); n != 0 {
		t.Errorf("without rules nothing is read: %d", n)
	}
}
