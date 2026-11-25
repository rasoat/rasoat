// Package scan is one scan of a directory or a site, whoever asked: the terminal command and the MCP tools differ only in
// which addresses they may read.
package scan

import (
	"errors"
	"fmt"
	"github.com/rasoat/rasoat/internal/core"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/rasoat/rasoat/internal/data"
	"github.com/rasoat/rasoat/internal/images"
	"github.com/rasoat/rasoat/internal/linux"
	"github.com/rasoat/rasoat/internal/osvdb"
	"github.com/rasoat/rasoat/internal/project"
	"github.com/rasoat/rasoat/internal/report"
	"github.com/rasoat/rasoat/internal/rules"
	"github.com/rasoat/rasoat/internal/site"
	"github.com/rasoat/rasoat/internal/websrv"
)

// UserAgent says what is asking, and nothing about what is being scanned.
var UserAgent = fmt.Sprintf("%s-cli/%s (+https://rasoat.com/en/check)", report.Tool, report.Version)

// NotATarget is a usage error.
type NotATarget struct{ Target string }

func (e *NotATarget) Error() string { return "Not a directory or a site address: " + e.Target }

// NotADir is a usage error: discover reads a directory, never an address.
type NotADir struct{ Target string }

func (e *NotADir) Error() string { return "Not a directory: " + e.Target }

// Discover walks a directory and lists what it names. It judges nothing and uses no network and no data file.
// rs is the user's own rules, or nil.
func Discover(target string, withPackages bool, rs *rules.Set) (*report.Inventory, error) {
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		return nil, &NotADir{target}
	}
	dir, _ := filepath.Abs(target)
	inv := report.InventoryOf(dir, project.WalkWith(dir, rs), withPackages)
	core.SanitizeTree(inv) // the one pass over the finished value: every renderer and agent channel reads it clean
	return inv, nil
}

var (
	hasScheme = core.NewRe(`(?i)^https?://`)
	looksHost = core.NewRe(`(?i)^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(/\S*)?$`)
)

// HostOptions say what Host scans. Root "": this machine, which must be Linux. Name, when set, is what the report calls
// the target in place of the root path.
type HostOptions struct {
	Root, Kernel, Name string
	Offline            bool
}

// Host scans a machine, or a mounted root.
func Host(o HostOptions) (*report.Report, error) {
	root, kernel, offline := o.Root, o.Kernel, o.Offline
	if root == "" && runtime.GOOS != "linux" {
		return nil, errors.New("this machine is not Linux: use --root with a mounted image or an extracted container tree")
	}
	shown := root
	if root == "" {
		root, shown = "/", "this machine"
	}
	if o.Name != "" {
		shown = o.Name
	}
	snapshot := func() *core.Snapshot { return data.Load(offline, UserAgent).Snapshot }
	exact := (&websrv.Judge{Snapshot: snapshot, Offline: offline, UserAgent: UserAgent}).Exact
	h, err := linux.Scan(linux.Options{Root: root, Kernel: kernel, Offline: offline, UserAgent: UserAgent, Snapshot: snapshot, Exact: exact})
	if err != nil {
		return nil, err
	}
	rep := report.Host(h, shown)
	core.SanitizeTree(rep)
	return rep, nil
}

// Target scans a directory if one has that name, a URL if it says so or looks like a host. public: an agent chose the
// address, perhaps from text it read, so never reach into the user's machine or network; returns *site.Refused then.
// rs is the user's own rules for a directory, or nil.
func Target(target string, offline, public bool, rs *rules.Set) (*report.Report, *data.Loaded, error) {
	dir, url := "", ""
	if hasScheme.MatchString(target) {
		url = target
	} else if st, err := os.Stat(target); err == nil && st.IsDir() {
		dir, _ = filepath.Abs(target)
	} else if looksHost.MatchString(target) {
		url = "https://" + target
	} else {
		return nil, nil, &NotATarget{target}
	}
	l := data.Load(offline, UserAgent)
	if dir != "" {
		w := project.WalkWith(dir, rs)
		// The release lines of the image families are in the linux index, one small file that names no project: fetched only
		// when this directory names an image or a CI pin whose family is judged from them.
		var lines map[string][]images.Release
		if slices.ContainsFunc(w.Images, func(i project.Image) bool { return i.Family != nil }) {
			if idx, _ := linux.LoadIndex(offline, UserAgent); idx != nil {
				lines = map[string][]images.Release{}
				for id, ls := range idx.Lines {
					for _, l := range ls {
						lines[id] = append(lines[id], images.Release(l))
					}
				}
			}
		}
		if slices.ContainsFunc(w.Images, func(i project.Image) bool { return i.Family != nil }) {
			lines = images.WithServerLines(lines, l.Snapshot) // the families endoflife.date has no table for: lines from their advisory lists
		}
		var d *osvdb.Outcome
		if len(w.Pkgs) > 0 {
			d = osvdb.Scan(w.Pkgs, offline, UserAgent)
		}
		exact := (&websrv.Judge{Snapshot: func() *core.Snapshot { return l.Snapshot }, Offline: offline, UserAgent: UserAgent}).Exact
		rep := report.Dir(dir, w, l, lines, d, exact)
		core.SanitizeTree(rep)
		return rep, l, nil
	}
	o, err := site.Inspect(url, site.NewGet(UserAgent, public), l.Snapshot.Requirements)
	if err != nil {
		return nil, nil, err
	}
	rep := report.Site(url, o, l)
	core.SanitizeTree(rep)
	return rep, l, nil
}
