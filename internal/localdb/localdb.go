// Package localdb is the local vulnerability database: the data files a scan can use, in the cache. Status reads the
// cache and sends nothing. Update downloads through the same functions a scan does, so a file is held to the same checks
// (older, or fewer records, loses) and a request names a file, never a project or a package.
package localdb

import (
	"slices"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/data"
	"github.com/rasoat/rasoat/internal/deps"
	"github.com/rasoat/rasoat/internal/linux"
	"github.com/rasoat/rasoat/internal/osvdb"
	"github.com/rasoat/rasoat/internal/report"
)

const (
	snapshotName = "snapshot-v1.json"
	indexName    = "index.json"
)

// ecosystems in the order a person reads them.
var ecosystems = []string{deps.NPM, deps.Cargo, deps.Go}

// File is one data file. Kind: snapshot, index, ecosystem, distro, kernel. Origin: cached, bundled (the snapshot copy
// built into the binary, used when no cached one is good), none. Records of the snapshot are its advisories summed over
// its products; of the index, the files it lists.
type File struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Origin  string `json:"origin"`
	Built   string `json:"built"`
	Records int    `json:"records"`
	AgeDays *int   `json:"age_days"`
	Stale   bool   `json:"stale"`
	Path    string `json:"path"`
}

// Status is the document `rasoat db status --json` prints.
type Status struct {
	Schema  int          `json:"schema"`
	Kind    string       `json:"kind"`
	Tool    report.Tool_ `json:"tool"`
	Cache   string       `json:"cache"`
	Files   []File       `json:"files"`
	Notices []string     `json:"notices"`
}

func fileOf(name, kind string) File {
	c, ok := linux.Inspect(name)
	f := File{Name: name, Kind: kind, Origin: "none", Path: c.Path}
	if !ok {
		return f
	}
	f.Origin, f.Built, f.Records = "cached", c.Built, c.Records
	days, stale := data.Age(c.Built)
	f.AgeDays, f.Stale = &days, stale
	return f
}

func snapshotFile() File {
	l := data.Load(true, "")
	f := File{Name: snapshotName, Kind: "snapshot", Origin: l.Origin, Built: l.Snapshot.Built, AgeDays: &l.AgeDays, Stale: l.Stale, Path: data.CachePath()}
	for _, n := range l.Snapshot.Counts() {
		f.Records += n
	}
	return f
}

func kindOf(name string) string {
	switch {
	case name == "linux-kernel.tsv.gz":
		return "kernel"
	case strings.HasPrefix(name, "eco-"):
		return "ecosystem"
	}
	return "distro"
}

// Inspect reads the cache: one row for the snapshot, the index and each ecosystem file, and one for each distro file
// already cached. It sends nothing.
func Inspect() Status {
	files := []File{snapshotFile(), fileOf(indexName, "index")}
	names := []string{}
	for _, e := range ecosystems {
		names = append(names, osvdb.File[e]+".tsv.gz")
	}
	for _, n := range linux.CachedNames() {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, n := range names {
		files = append(files, fileOf(n, kindOf(n)))
	}
	return Status{Schema: 1, Kind: "db_status", Tool: report.Tool_{Name: report.Tool, Version: report.Version}, Cache: data.CacheDir(), Files: files, Notices: core.NOTICES}
}

// Change is what an update did to one file. Result: added, updated, unchanged, or kept: the download did not come or was
// refused, the old file stays, and Problem says why (unreachable, invalid, older, lost-records).
type Change struct {
	Name          string  `json:"name"`
	Result        string  `json:"result"`
	Problem       *string `json:"problem"`
	BuiltBefore   string  `json:"built_before"`
	BuiltAfter    string  `json:"built_after"`
	RecordsBefore int     `json:"records_before"`
	RecordsAfter  int     `json:"records_after"`
}

// Updated is the document `rasoat db update --json` prints. ExitCode is 2 when any file was kept for a problem.
type Updated struct {
	Schema   int          `json:"schema"`
	Kind     string       `json:"kind"`
	Tool     report.Tool_ `json:"tool"`
	Files    []Change     `json:"files"`
	Failed   int          `json:"failed"`
	ExitCode int          `json:"exit_code"`
}

// Plan is said before the distro files are downloaded: how many, and the records they hold. The index carries no sizes.
type Plan struct {
	Files, Records int
}

func changed(name string, before, after File, problem string) Change {
	c := Change{Name: name, BuiltBefore: before.Built, BuiltAfter: after.Built, RecordsBefore: before.Records, RecordsAfter: after.Records}
	switch {
	case problem != "":
		c.Result, c.Problem = "kept", &problem
	case before.Origin != "cached":
		c.Result = "added"
	case before.Built == after.Built && before.Records == after.Records:
		c.Result = "unchanged"
	default:
		c.Result = "updated"
	}
	return c
}

// Update refreshes the snapshot, the index and the ecosystem files, and with all, every distro file the index lists
// (announce is told how many before the first). Each is held to the checks a scan holds a download to.
func Update(all bool, userAgent string, announce func(Plan)) Updated {
	var out []Change
	one := func(name string, look func() File, refresh func() string) {
		before := look()
		problem := refresh()
		out = append(out, changed(name, before, look(), problem))
	}
	file := func(name, kind string) {
		one(name, func() File { return fileOf(name, kind) }, func() string { return linux.Refresh(name, userAgent).Problem })
	}
	one(snapshotName, snapshotFile, func() string {
		if l := data.Refresh(userAgent); l.Problem != nil {
			return *l.Problem
		}
		return ""
	})
	file(indexName, "index")
	for _, e := range ecosystems {
		file(osvdb.File[e]+".tsv.gz", "ecosystem")
	}
	if all {
		idx, _ := linux.LoadIndex(true, userAgent) // the index just refreshed, read from the cache
		var names []string
		plan := Plan{}
		if idx != nil {
			for id, records := range idx.Files {
				if !strings.HasPrefix(id, "eco-") {
					names = append(names, id+".tsv.gz")
					plan.Records += records
				}
			}
			slices.Sort(names)
			plan.Files = len(names)
		}
		if announce != nil {
			announce(plan)
		}
		for _, n := range names {
			file(n, kindOf(n))
		}
		if idx == nil {
			p := "index-not-available"
			out = append(out, Change{Name: "distro-files", Result: "kept", Problem: &p})
		}
	}
	u := Updated{Schema: 1, Kind: "db_update", Tool: report.Tool_{Name: report.Tool, Version: report.Version}, Files: out}
	for _, c := range out {
		if c.Problem != nil {
			u.Failed++
		}
	}
	if u.Failed > 0 {
		u.ExitCode = 2
	}
	return u
}
