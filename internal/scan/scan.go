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

	"github.com/rasoat/rasoat/internal/data"
	"github.com/rasoat/rasoat/internal/linux"
	"github.com/rasoat/rasoat/internal/project"
	"github.com/rasoat/rasoat/internal/report"
	"github.com/rasoat/rasoat/internal/site"
)

// UserAgent says what is asking, and nothing about what is being scanned.
var UserAgent = fmt.Sprintf("%s-cli/%s (+https://rasoat.com/en/check)", report.Tool, report.Version)

// NotATarget is a usage error.
type NotATarget struct{ Target string }

func (e *NotATarget) Error() string { return "Not a directory or a site address: " + e.Target }

var (
	hasScheme = core.NewRe(`(?i)^https?://`)
	looksHost = core.NewRe(`(?i)^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(/\S*)?$`)
)

// Host scans a machine, or a mounted root. root "": this machine, which must be Linux.
func Host(root, kernel string, offline bool) (*report.Report, error) {
	if root == "" && runtime.GOOS != "linux" {
		return nil, errors.New("this machine is not Linux: use --root with a mounted image or an extracted container tree")
	}
	shown := root
	if root == "" {
		root, shown = "/", "this machine"
	}
	h, err := linux.Scan(linux.Options{Root: root, Kernel: kernel, Offline: offline, UserAgent: UserAgent})
	if err != nil {
		return nil, err
	}
	return report.Host(h, shown), nil
}

// Target scans a directory if one has that name, a URL if it says so or looks like a host. public: an agent chose the
// address, perhaps from text it read, so never reach into the user's machine or network; returns *site.Refused then.
func Target(target string, offline, public bool) (*report.Report, *data.Loaded, error) {
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
		return report.Dir(dir, project.Walk(dir), l), l, nil
	}
	o, err := site.Inspect(url, site.NewGet(UserAgent, public), l.Snapshot.Requirements)
	if err != nil {
		return nil, nil, err
	}
	return report.Site(url, o, l), l, nil
}
