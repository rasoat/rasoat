// Package websrv judges an exact version of a web server or proxy, named by an image tag or a vendor package, from the
// advisory data the CLI already carries: the web servers' lists (the snapshot's servers, one shape for every product) and the OSV Go data (the eco-go file) for
// Caddy and Traefik, which are Go modules. It answers images.ExactJudge.
package websrv

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/deps"
	"github.com/rasoat/rasoat/internal/images"
	"github.com/rasoat/rasoat/internal/linux"
	"github.com/rasoat/rasoat/internal/osvdb"
)

// Judge holds how to get the data, lazily: a scan that names no web server loads nothing.
type Judge struct {
	Snapshot  func() *core.Snapshot
	Offline   bool
	UserAgent string

	snapOnce sync.Once
	snap     *core.Snapshot
	ecoOnce  sync.Once
	eco      []byte
}

// module is the Go module a family's releases are published as, by the release's major version. Caddy 1 and Traefik 1 are
// other modules with other paths; they are not judged here.
func module(family, version string) (string, bool) {
	major, _, _ := strings.Cut(version, ".")
	host := "github.com"
	switch {
	case family == "caddy" && major == "2":
		return host + "/caddyserver/caddy/v2", true
	case family == "traefik" && (major == "2" || major == "3"):
		return host + "/traefik/traefik/v" + major, true
	}
	return "", false
}

// count: "1 advisory", "10 advisories".
func count(n int) string {
	if n == 1 {
		return "1 advisory"
	}
	return fmt.Sprintf("%d advisories", n)
}

func verdict(family, version, status string) core.Verdict {
	return core.Verdict{Product: family, Version: &version, Status: status, Advisories: []core.VerdictAdvisory{}}
}

// snapshot is the site snapshot, loaded once; nil when there is none to be had.
func (j *Judge) snapshot() *core.Snapshot {
	if j.Snapshot == nil {
		return nil
	}
	j.snapOnce.Do(func() { j.snap = j.Snapshot() })
	return j.snap
}

// Exact is images.ExactJudge. A family whose id is in the snapshot's `servers` is judged from that list: adding a product is
// a family registration (images/family.go) and its list in the snapshot, and nothing here.
func (j *Judge) Exact(family, version string) (core.Verdict, string, bool) {
	switch family {
	case "caddy", "traefik":
		return j.goModule(family, version)
	case "openresty":
		return j.openresty(version)
	}
	return j.server(family, version)
}

// server judges a family from its list in the snapshot. Severity arrives normalised and every hit carries its own link.
func (j *Judge) server(family, version string) (core.Verdict, string, bool) {
	snap := j.snapshot()
	if snap == nil || snap.Servers[family] == nil {
		return core.Verdict{}, "", false
	}
	list := snap.Servers[family]
	res, ok := core.ServerVerdict(version, list)
	if !ok {
		return core.Verdict{}, "", false
	}
	v := verdict(family, version, res.Status)
	host := list.Source
	if u, err := url.Parse(list.Source); err == nil && u.Host != "" {
		host = u.Host
	}
	source := fmt.Sprintf("the %s list, fetched %s", host, list.Fetched)
	name := images.Name(family)
	if res.Status == core.OK {
		return v, fmt.Sprintf("no advisory in %s reaches %s %s", source, name, version), true
	}
	for _, h := range res.Hits {
		v.Advisories = append(v.Advisories, core.VerdictAdvisory{ID: h.ID, Severity: h.Severity, Summary: h.Title, URL: h.URL})
	}
	sort.SliceStable(v.Advisories, func(a, b int) bool {
		return core.SeverityRank(v.Advisories[a].Severity) < core.SeverityRank(v.Advisories[b].Severity)
	})
	if res.Fix != "" {
		v.Fix = &res.Fix
	} else {
		v.NoFix = true
	}
	return v, fmt.Sprintf("%s in %s reach %s %s", count(len(res.Hits)), source, name, version), true
}

func (j *Judge) goModule(family, version string) (core.Verdict, string, bool) {
	mod, ok := module(family, version)
	if !ok || !core.ValidVersion("v"+version) {
		return core.Verdict{}, "", false
	}
	j.ecoOnce.Do(func() { j.eco, _ = linux.LoadFile(osvdb.File[deps.Go], j.Offline, j.UserAgent) })
	if j.eco == nil {
		return core.Verdict{}, "", false
	}
	ranges := osvdb.Pick(j.eco, map[string]bool{mod: true})[mod]
	res := osvdb.Judge(version, ranges)
	v := verdict(family, version, core.OK)
	// An image or package also holds the Go toolchain and the plugins built in: only the module itself is judged.
	scope := "Go module " + mod + " (the Go toolchain and any plugins are not judged)"
	if len(res.Hits) == 0 {
		return v, "no advisory in the OSV Go data reaches " + scope, true
	}
	v.Status = core.Vulnerable
	for _, h := range res.Hits {
		if url, ok := osvdb.AdvisoryURL(h.ID); ok {
			v.Advisories = append(v.Advisories, core.VerdictAdvisory{ID: h.ID, Severity: h.Severity, Summary: strings.Join(h.Aliases, ", "), URL: url})
		}
	}
	if res.Fix != "" {
		fix := res.Fix
		v.Fix = &fix
	} else {
		v.NoFix = res.NoFix
	}
	return v, fmt.Sprintf("%s in the OSV Go data reach %s", count(len(res.Hits)), scope), true
}

// openresty judges an OpenResty release as the nginx it bundles: A.B.C.D is nginx A.B.C plus OpenResty's own patch
// level, so the first three numbers go to the nginx list. OpenResty's point releases can carry fixes of their own that this
// does not see, and the row says so.
func (j *Judge) openresty(version string) (core.Verdict, string, bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 4 {
		return core.Verdict{}, "", false
	}
	nginx := strings.Join(parts[:3], ".")
	v, how, ok := j.server("nginx", nginx)
	if !ok {
		return core.Verdict{}, "", false
	}
	v.Product, v.Version = "openresty", &version
	how = fmt.Sprintf("judged as its bundled nginx %s; OpenResty point releases may carry their own patches; %s", nginx, how)
	if v.Fix != nil {
		// The fix is an nginx release: no OpenResty version is named after it, so none is offered as the upgrade.
		how += fmt.Sprintf("; nginx fixes it in %s: move to an OpenResty release built on that nginx", *v.Fix)
		v.Fix = nil
	}
	return v, how, true
}
