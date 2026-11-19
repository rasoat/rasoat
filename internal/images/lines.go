package images

import "github.com/rasoat/rasoat/internal/core"

// WithServerLines adds the release lines of the snapshot's server lists for every family flagged NoEOL (endoflife.date has no
// table for Angie, Apache Traffic Server, Varnish Cache). A line the list
// marks ended carries no date, only EndedLine. lines may be nil; the result is never shared with the argument.
func WithServerLines(lines map[string][]Release, snap *core.Snapshot) map[string][]Release {
	if snap == nil || len(snap.Servers) == 0 {
		return lines
	}
	out := make(map[string][]Release, len(lines)+len(snap.Servers))
	for id, ls := range lines {
		out[id] = ls
	}
	for id, list := range snap.Servers {
		if f := ByID(id); f == nil || !f.NoEOL {
			continue
		}
		for _, l := range list.Lines {
			r := Release{Cycle: l.Line, Latest: l.Latest}
			if l.EOL {
				r.EOL = EndedLine
			}
			out[id] = append(out[id], r)
		}
	}
	return out
}
