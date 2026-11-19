package linux

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/images"
)

// A vendor package is judged as the product it is, never against the distro's fixes (see origin.go). The vendor products named below
// have a verdict in this program (php, node, postgresql, mariadb, nginx, Caddy, httpd, HAProxy, Varnish, OpenResty, Angie); every other vendor package is counted in a note, never read as clean.

// vendorKey names a vendor from an apt Origin, an rpm Vendor or a marker. "" for one this program does not route.
func vendorKey(label string) string {
	low := strings.ToLower(label)
	for _, k := range []struct{ frag, key string }{
		{"ondrej", "sury"}, {"sury", "sury"}, {"postgresql", "pgdg"}, {"pgdg", "pgdg"},
		{"node source", "nodesource"}, {"nodesource", "nodesource"}, {"maria", "mariadb"}, {"remi", "remi"},
		{"nginx", "nginx"}, {"caddy", "caddy"},
		// Release Origins read from the vendors' own repos: LP-PPA-vbernat-haproxy-3.2 and PPA-haproxy (haproxy.debian.net),
		// packagecloud.io/varnishcache/varnish75, openresty.org, angie.
		{"haproxy", "haproxy"}, {"varnishcache", "varnish"}, {"openresty", "openresty"}, {"angie", "angie"},
	} {
		if strings.Contains(low, k.frag) {
			return k.key
		}
	}
	return ""
}

var (
	phpSource  = regexp.MustCompile(`^php\d+\.\d+$`) // Sury names a source for each PHP line
	pgSource   = regexp.MustCompile(`^postgresql-?\d+$`)
	mariaSrc   = regexp.MustCompile(`^mariadb(-\d+(\.\d+)*)?$`)
	plainVer   = regexp.MustCompile(`^\d+(\.\d+)*$`)
	notePieces = strings.NewReplacer(" ", "-", ":", "-")
)

// vendorProduct: the product a vendor's source package is, by the vendor and the source's name together. A name alone is
// the distro's too, and a vendor alone says nothing about which of its packages this is.
func vendorProduct(key, source string) string {
	switch {
	case key == "sury" && phpSource.MatchString(source), key == "remi" && source == "php":
		return "php"
	case key == "nodesource" && source == "nodejs":
		return "node"
	case key == "pgdg" && pgSource.MatchString(source):
		return "postgresql"
	case key == "mariadb" && mariaSrc.MatchString(source):
		return "mariadb"
	case key == "nginx" && source == "nginx", key == "caddy" && source == "caddy":
		return source
	case key == "haproxy" && source == "haproxy", key == "varnish" && source == "varnish",
		key == "openresty" && source == "openresty", key == "angie" && source == "angie":
		return source
	case key == "sury" && source == "apache2": // ondrej's Apache build: 2.4.71-1+ubuntu24.04.1+deb.sury.org+1
		return "apache-http-server"
	}
	return ""
}

// upstreamVersion strips an epoch, a Debian or rpm revision and a vendor suffix: "1:11.8.9+maria~ubu2404" is 11.8.9,
// "16.16-1.pgdg24.04+1" is 16.16, "8.3.27-1+ubuntu24.04.1+deb.sury.org+1" is 8.3.27. "" when no plain number is left.
func upstreamVersion(v string) string {
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexAny(v, "+~"); i >= 0 {
		v = v[:i]
	}
	if !plainVer.MatchString(v) {
		return ""
	}
	return v
}

type vendorGroup struct {
	product, version string
	origin, decided  string
	bins             []string
}

// judgeVendors judges the vendor packages. upgrade: the packages of a row that is vulnerable, which an upgrade fixes.
func judgeVendors(pkgs []Package, index *Index, o Options) (rows []Finding, notes, upgrade []string) {
	groups := map[string]*vendorGroup{}
	counts := map[string]int{}
	for _, p := range pkgs {
		key := vendorKey(p.Vendor)
		if key == "" { // an Origin that names nothing useful: the version string may
			key = markerVendor(p.Version)
		}
		product := vendorProduct(key, p.Source)
		version := upstreamVersion(p.SourceVersion)
		if product == "" || version == "" {
			counts[p.Vendor]++
			continue
		}
		k := product + " " + version
		g := groups[k]
		if g == nil {
			g = &vendorGroup{product: product, version: version, origin: p.Vendor, decided: p.Decided}
			groups[k] = g
		}
		g.bins = append(g.bins, p.Name)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var snapshot *core.Snapshot
	loaded := false
	load := func() *core.Snapshot { // the snapshot is loaded once, however many rows ask
		if !loaded && o.Snapshot != nil {
			snapshot, loaded = o.Snapshot(), true
		}
		return snapshot
	}
	var lines map[string][]images.Release
	for _, k := range keys {
		g := groups[k]
		var v core.Verdict
		how := ""
		switch g.product {
		case "php", "node":
			if load() == nil {
				reason := "no-advisory-data"
				version := g.version
				v = core.Verdict{Product: g.product, Version: &version, Status: core.Unknown, Reason: &reason, Advisories: []core.VerdictAdvisory{}}
			} else {
				version := g.version
				v = core.VerdictFor(g.product, &version, load(), o.Today)
			}
		default:
			if lines == nil && index != nil {
				lines = map[string][]images.Release{}
				for id, ls := range index.Lines {
					for _, l := range ls {
						lines[id] = append(lines[id], images.Release(l))
					}
				}
				lines = images.WithServerLines(lines, load()) // the families endoflife.date has no table for: lines from their advisory lists
			}
			image := map[string]string{"postgresql": "postgres", "mariadb": "mariadb", "nginx": "nginx", "caddy": "caddy", "apache-http-server": "httpd",
				"haproxy": "haproxy", "varnish": "varnish", "angie": "angie", "openresty": "openresty/openresty"}[g.product]
			v, how = images.JudgeWith(images.ParseRef(image+":"+g.version), lines, o.Today, o.Exact)
		}
		sort.Strings(g.bins)
		built := fmt.Sprintf("vendor build %s, origin read by %s", g.origin, g.decided)
		if how != "" {
			built += "; " + how
		}
		rows = append(rows, Finding{Verdict: v, Installed: append(g.bins, "origin:"+g.origin), How: built})
		if v.Status == core.Vulnerable {
			upgrade = append(upgrade, g.bins...)
		}
	}
	for origin, n := range counts {
		notes = append(notes, fmt.Sprintf("vendor-not-judged:%s:%d", notePieces.Replace(origin), n))
	}
	sort.Strings(notes)
	return rows, notes, upgrade
}
