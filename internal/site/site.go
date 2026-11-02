package site

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
)

// RuntimeFinding is a runtime behind a site: exact when a response header names it, otherwise a bound (Min) the framework imposes.
type RuntimeFinding struct {
	Runtime string
	Version string
	How     string
	Min     string
}

// Outcome is what reading a site came to. Kind: unreachable, blocked or result.
type Outcome struct {
	Kind          string
	Status        *int
	Cause         string // timeout, tls, network
	By            string
	URL           string
	Findings      []Finding
	Runtimes      []RuntimeFinding
	TLSUnverified bool
}

var (
	phpIn      = core.NewRe(`(?i)\bPHP/(\d+\.\d+(?:\.\d+)?)`)
	phpWord    = core.NewRe(`(?i)\bPHP\b`)
	bunWord    = core.NewRe(`(?i)\bBun\b`)
	bunIn      = core.NewRe(`(?i)\bBun/(\d+\.\d+\.\d+)`)
	nodeServer = core.NewRe(`(?i)\b(Express|Next\.js|Nuxt|Koa|Fastify|NestJS)\b`)
	number     = core.NewRe(`\d+\.\d+\.\d+|\d+\.\d+|\d+`)
	cloudflare = core.NewRe(`(?i)cloudflare`)
	akamai     = core.NewRe(`(?i)akamai`)
	devSuffix  = core.NewRe(`-.*$`)
)

func headerRuntimes(page *Resp) []*RuntimeFinding {
	h := page.Headers
	said := h["x-powered-by"] + " " + h["server"]
	var out []*RuntimeFinding
	if m := phpIn.FindStringSubmatch(said); m != nil {
		how := "Server"
		if phpIn.MatchString(h["x-powered-by"]) {
			how = "X-Powered-By"
		}
		out = append(out, &RuntimeFinding{Runtime: "php", Version: core.NormalizeRuntime(m[1]), How: how})
	} else if phpWord.MatchString(said) {
		out = append(out, &RuntimeFinding{Runtime: "php", How: "X-Powered-By"})
	}
	if bunWord.MatchString(said) {
		v := ""
		if m := bunIn.FindStringSubmatch(said); m != nil {
			v = m[1]
		}
		out = append(out, &RuntimeFinding{Runtime: "bun", Version: v, How: "Server"})
	} else if nodeServer.MatchString(h["x-powered-by"]) {
		out = append(out, &RuntimeFinding{Runtime: "node", How: "X-Powered-By"})
	}
	return out
}

// minOfRange is the smallest version an engines range admits: "^18.18.0 || ^19.8.0 || >= 20.0.0" gives 18.18.0.
func minOfRange(r string) string {
	var vs []string
	for _, n := range number.FindAllString(r, -1) {
		if !strings.Contains(n, ".") {
			n += ".0"
		}
		vs = append(vs, core.NormalizeRuntime(n))
	}
	sort.SliceStable(vs, func(i, j int) bool { return core.Order(vs[i], vs[j]) < 0 })
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func inferRuntimes(c *Crawl, findings []Finding, req core.Requirements) []RuntimeFinding {
	found := headerRuntimes(c.Page)
	byName := func(name string) *RuntimeFinding {
		for _, r := range found {
			if r.Runtime == name {
				return r
			}
		}
		return nil
	}
	for _, f := range findings {
		if f.Framework == "next" && f.Version != "" && byName("bun") == nil {
			base := devSuffix.ReplaceAllString(f.Version, "")
			for i := len(req.Next) - 1; i >= 0; i-- { // this release or the closest before
				if core.Order(req.Next[i].V, base) <= 0 {
					if lowest := minOfRange(req.Next[i].Node); lowest != "" {
						node := byName("node")
						if node == nil {
							node = &RuntimeFinding{Runtime: "node"}
							found = append(found, node)
						}
						node.Min = lowest
					}
					break
				}
			}
		}
		if f.Framework == "wordpress" && f.Version != "" {
			php := byName("php")
			parts := strings.Split(f.Version, ".")
			need := req.WordPress[strings.Join(parts[:min(2, len(parts))], ".")]
			if need != "" && (php == nil || php.Version == "") {
				if php == nil {
					php = &RuntimeFinding{Runtime: "php"}
					found = append(found, php)
				}
				php.Min = core.NormalizeRuntime(need)
			}
		}
	}
	out := make([]RuntimeFinding, len(found))
	for i, r := range found {
		out[i] = *r
	}
	return out
}

// Inspect reads one site. Bot protection is reported and never fought. It returns *Refused unchanged, and names any other failure.
func Inspect(target string, get Get, req core.Requirements) (Outcome, error) {
	c, err := crawl(target, get, 30)
	if err != nil {
		var refused *Refused
		if errors.As(err, &refused) {
			return Outcome{}, refused
		}
		return Outcome{Kind: "unreachable", Cause: causeOf(err)}, nil
	}
	p := c.Page
	switch p.Status {
	case 401, 403, 429, 503:
		st := p.Status
		return Outcome{Kind: "blocked", Status: &st, By: blocker(p.Headers)}, nil
	}
	if p.Status >= 400 {
		st := p.Status
		return Outcome{Kind: "unreachable", Status: &st}, nil
	}
	findings := detect(c)
	return Outcome{Kind: "result", URL: p.URL, Findings: findings, Runtimes: inferRuntimes(c, findings, req), TLSUnverified: p.TLSUnverified}, nil
}

func blocker(h map[string]string) string {
	switch {
	case h["cf-mitigated"] != "" || cloudflare.MatchString(h["server"]):
		return "Cloudflare"
	case akamai.MatchString(h["server"]) || h["akamai-grn"] != "":
		return "Akamai"
	}
	return ""
}

func causeOf(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	var cert *tls.CertificateVerificationError
	var host x509.HostnameError
	var inv x509.CertificateInvalidError
	var rec tls.RecordHeaderError
	if errors.As(err, &cert) || errors.As(err, &host) || errors.As(err, &inv) || errors.As(err, &rec) {
		return "tls"
	}
	return "network"
}

// StatusText renders a site's status for a message.
func StatusText(st *int) string {
	if st == nil {
		return ""
	}
	return strconv.Itoa(*st)
}
