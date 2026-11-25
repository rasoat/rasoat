package images

import (
	"strings"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
)

// The tag schemes of the web server and proxy images, as Docker Hub listed them on 2026-11-19.
func TestParseRefProxies(t *testing.T) {
	for raw, want := range map[string]string{
		"envoyproxy/envoy:v1.36.2":                     "envoy exact 1.36.2",
		"envoyproxy/envoy:distroless-v1.36.2":          "envoy exact 1.36.2",
		"envoyproxy/envoy:contrib-distroless-v1.36.13": "envoy exact 1.36.13",
		"envoyproxy/envoy:google-vrp-v1.36.12":         "envoy exact 1.36.12",
		"envoyproxy/envoy:debug-v1.36-latest":          "envoy line 1.36",
		"envoyproxy/envoy:distroless-dev":              "envoy unpinned ",
		"envoyproxy/envoy:latest":                      "envoy unpinned ",
		"haproxy:3.2.27":                               "haproxy exact 3.2.27",
		"haproxy:3.2.27-alpine":                        "haproxy exact 3.2.27",
		"haproxy:3.4-trixie":                           "haproxy line 3.4",
		"haproxy:lts":                                  "haproxy unpinned ",
		"haproxy:3.5-dev13-alpine":                     "haproxy line 3.5",
		"varnish:9.1.0-2":                              "varnish exact 9.1.0",
		"varnish:9.0":                                  "varnish line 9.0",
		"varnish:stable":                               "varnish unpinned ",
		"trafficserver/trafficserver:10.2.1":           "apache-traffic-server exact 10.2.1",
		"docker.angie.software/angie:1.11.8-alpine":    "angie exact 1.11.8",
		"docker.angie.software/angie:minimal":          "angie unpinned ",
		"openresty/openresty:1.27.1.2-alpine":          "openresty exact 1.27.1.2",
		"openresty/openresty:1.27.1.2-13-bookworm-fat": "openresty exact 1.27.1.2",
		"openresty/openresty:1.27.1-alpine":            "openresty line 1.27.1",
		"ubuntu/squid:6.13-25.04_beta":                 "squid line 6.13",
		"litespeedtech/openlitespeed:1.9.4-lsphp84":    "openlitespeed exact 1.9.4",
		"litespeedtech/openlitespeed:latest-lsphp82":   "openlitespeed unpinned ",
		"litespeedtech/litespeed:6.3.7-lsphp83":        "litespeed exact 6.3.7",
		"kong:3.9.4":                                   "kong-gateway exact 3.9.4",
		"kong/kong-gateway:3.16.0.2-ubuntu":            "kong-gateway exact 3.16.0.2",
		"kong:ubuntu":                                  "kong-gateway unpinned ",
		"valkey/valkey:9.2-alpine3.24":                 "valkey line 9.2",
		"valkey/valkey:9.2.1":                          "valkey exact 9.2.1",
		"valkey/valkey:unstable":                       "valkey unpinned ",
		"clamav/clamav:1.4.7-debian13-slim":            "clamav exact 1.4.7",
		"clamav/clamav:1.4-debian":                     "clamav line 1.4",
		"louislam/uptime-kuma:2.0.2":                   "uptime-kuma exact 2.0.2",
		"louislam/uptime-kuma:nightly":                 "uptime-kuma unpinned ",
	} {
		if got := row(ParseRef(raw)); got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}

func TestRecognisedOnlyFamiliesAreNeverOk(t *testing.T) {
	for _, raw := range []string{"litespeedtech/openlitespeed:1.9.4-lsphp84", "litespeedtech/litespeed:6.3.7-lsphp83", "valkey/valkey:9.2.1", "clamav/clamav:1.4.7-debian13-slim", "louislam/uptime-kuma:2.0.2"} {
		v, how := Judge(ParseRef(raw), nil, "2026-11-19")
		if v.Status != core.Unknown || v.Reason == nil || *v.Reason != ReasonNoAdvisory || !strings.Contains(how, "no advisory data and no release-line data") {
			t.Errorf("%s: %+v %q", raw, v, how)
		}
	}
}

// A line the product's own list marks ended is unsupported, and one the list does not name is not listed.
func TestServerListLinesJudgeAnEndedLine(t *testing.T) {
	snap := &core.Snapshot{Servers: map[string]*core.ServerAdvisories{
		"varnish": {Product: "varnish", Lines: []core.ServerLine{{Line: "9.0", Latest: "9.0.4"}, {Line: "7.5", EOL: true, Latest: "7.5.0"}}},
		"nginx":   {Product: "nginx", Lines: []core.ServerLine{{Line: "1.30", EOL: true}}},
	}}
	lines := WithServerLines(nil, snap)
	if len(lines["nginx"]) != 0 {
		t.Errorf("a family endoflife.date knows keeps the index's lines: %v", lines["nginx"])
	}
	v, how := Judge(ParseRef("varnish:7.5.0"), lines, "2026-11-19")
	if v.Status != core.Unsupported || v.Fix == nil || *v.Fix != "9.0.4" || how != "Varnish Cache line 7.5 has ended" {
		t.Errorf("%+v %q", v, how)
	}
	if v, _ := Judge(ParseRef("varnish:9.0.4"), lines, "2026-11-19"); v.Status != core.Unknown {
		t.Errorf("a live line with no advisory ruling here is never ok: %+v", v)
	}
}
