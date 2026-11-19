package data

import (
	"encoding/json"
	"maps"
	"testing"
)

func TestMetaEqualsTheSnapshotItDescribes(t *testing.T) {
	var m meta
	if err := json.Unmarshal(bundledMeta, &m); err != nil {
		t.Fatal(err)
	}
	s := Bundled()
	if m.Built != s.Built || !maps.Equal(m.Counts, s.Counts()) {
		t.Errorf("meta %v, snapshot %s %v", m, s.Built, s.Counts())
	}
}
