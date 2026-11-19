package images

import "github.com/rasoat/rasoat/internal/core"

// ExactJudge judges one exact version of a family from advisory data this package does not hold (nginx.org's list, the OSV
// data of a Go module). ok false: there is no such data for this family, or it could not be had; the release line judges.
type ExactJudge func(family, version string) (v core.Verdict, how string, ok bool)

// JudgeWith is Judge for a reference that may have advisory data behind it. An exact tag or package version of a family
// with such data gets ok or vulnerable. A floating tag keeps the release-line answer, which already says the tag floats.
// A version no advisory reaches on a line that no longer gets fixes is still unsupported: ok would mislead.
func JudgeWith(r Ref, lines map[string][]Release, today string, exact ExactJudge) (core.Verdict, string) {
	if exact == nil || r.Kind != Exact {
		v, how := Judge(r, lines, today)
		if exact != nil && r.Family != nil && r.Family.Advisories && (r.Kind == Line || r.Kind == Unpinned) {
			// Same status and reason as any floating tag; this only says what pinning would buy.
			float := "the tag floats, so the version it runs depends on when it was pulled; pin an exact version to be judged against advisories"
			if how != "" {
				how += "; "
			}
			how += float
		}
		return v, how
	}
	v, how, ok := exact(r.Family.ID, r.Version)
	if !ok {
		return Judge(r, lines, today)
	}
	if v.Status == core.OK {
		if lv, lhow := Judge(r, lines, today); lv.Status == core.Unsupported {
			return lv, lhow + "; no advisory in this data reaches it, but the line gets no more fixes"
		}
	}
	return v, how
}
