package linux

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

// The file is what dpkg, rpm and apk answered, in their own containers (scripts/linux/verify-vercmp.ts).
func TestComparatorsEqualTheRealTools(t *testing.T) {
	f, err := os.Open("testdata/vercmp.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string][][]any
	if err := json.NewDecoder(z).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	for family, rows := range doc {
		bad := 0
		for _, r := range rows {
			a, b, want := r[0].(string), r[1].(string), int(r[2].(float64))
			if got := Compare(family, a, b); got != want {
				bad++
				if bad <= 15 {
					t.Errorf("%s: %q vs %q = %d, the tool says %d", family, a, b, got, want)
				}
			}
		}
		t.Logf("%s: %d pairs, %d differ", family, len(rows), bad)
	}
}
