package images

import (
	"slices"
	"testing"

	"github.com/rasoat/rasoat/internal/core"
)

// row is a Ref as a test reads it: family, kind, version.
func row(r Ref) string {
	id := "-"
	if r.Family != nil {
		id = r.Family.ID
	}
	return id + " " + [...]string{"exact", "line", "unpinned"}[r.Kind] + " " + r.Version
}

func rows(refs []Ref) []string {
	out := []string{}
	for _, r := range refs {
		if r.Unresolved {
			out = append(out, "unresolved "+r.Raw)
		} else {
			out = append(out, row(r))
		}
	}
	return out
}

func TestParseRef(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres:16.4":                             "postgresql exact 16.4",
		"postgres:16":                               "postgresql line 16",
		"postgres:16-alpine":                        "postgresql line 16",
		"postgres:17.12-alpine@sha256:abc":          "postgresql exact 17.12",
		"redis:7-alpine":                            "redis line 7",
		"redis:7.2.4":                               "redis exact 7.2.4",
		"docker.io/library/nginx:1.24.0-alpine3.19": "nginx exact 1.24.0",
		"nginx:alpine":                              "nginx unpinned ",
		"nginx":                                     "nginx unpinned ",
		"postgres:latest":                           "postgresql unpinned ",
		"postgres@sha256:abc":                       "postgresql unpinned ",
		"timescale/timescaledb:2.32.0-pg17@sha256:6a6b": "postgresql line 17",
		"pgvector/pgvector:0.8.7-pg17":                  "postgresql line 17",
		"pgvector/pgvector:0.8.7":                       "postgresql unpinned ",
		"tensorchord/vchord-suite:pg17-latest":          "postgresql line 17",
		"clickhouse/clickhouse-server:26.8.36.3":        "clickhouse exact 26.8.36.3",
		"debian:bookworm-slim":                          "debian line 12",
		"debian:12-slim@sha256:99c0":                    "debian line 12",
		"debian:12.5":                                   "debian line 12.5",
		"ubuntu:jammy-20240111":                         "ubuntu line 22.04",
		"ubuntu:22.04":                                  "ubuntu line 22.04",
		"alpine:3.19.1":                                 "alpine-linux line 3.19.1",
		"rust:1-bookworm":                               "rust line 1",
		"rust:1.96-bookworm":                            "rust line 1.96",
		"rust:1.78.0":                                   "rust exact 1.78.0",
		"golang:1.22-alpine":                            "go line 1.22",
		"caddy:2":                                       "caddy line 2",
		"caddy:2.8.4":                                   "caddy exact 2.8.4",
		"httpd:2.4.71-alpine":                           "apache-http-server exact 2.4.71",
		"httpd:2.4":                                     "apache-http-server line 2.4",
		"httpd:alpine":                                  "apache-http-server unpinned ",
		"httpd:latest":                                  "apache-http-server unpinned ",
		"prom/prometheus:v2.51.0":                       "prometheus exact 2.51.0",
		"grafana/grafana:11.0.0":                        "grafana exact 11.0.0",
		"mariadb:11":                                    "mariadb line 11",
		"oven/bun:1.4.4-slim":                           "bun exact 1.4.4",
		"oven/bun:1":                                    "bun line 1",
		"oven/bun@sha256:9dba":                          "bun unpinned ",
		"node:22-alpine":                                "node line 22",
		"node:lts":                                      "node unpinned ",
		"php:8.3-fpm-bookworm":                          "php line 8.3",
		"wordpress:6-apache":                            "wordpress line 6",
		"wordpress:6.4.3-php8.2-apache":                 "wordpress exact 6.4.3",
		"ghcr.io/acme/api:1.2.3":                        "- exact ",
		"axllent/mailpit:latest":                        "- exact ",
		"registry.example.com:5000/team/postgres:16":    "- exact ",
	} {
		got := row(ParseRef(raw))
		if want == "- exact " {
			if ParseRef(raw).Family != nil {
				t.Errorf("%s: judged as %s", raw, got)
			}
			continue
		}
		if got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
}

// Real text from our own repos, with private image names replaced.
const dockerfile = `# syntax=docker/dockerfile:1
ARG BUN_VERSION=1.4.4
ARG REGISTRY
FROM oven/bun:${BUN_VERSION} AS base
WORKDIR /app
FROM base AS deps
FROM --platform=$BUILDPLATFORM rust:1.96-bookworm@sha256:a339861ae AS build
FROM scratch AS out
FROM ${REGISTRY}/acme/base:1 AS private
FROM oven/bun:1.4.4-slim AS runtime
ARG GIT_SHA=unknown
FROM debian:bookworm-slim
`

func TestDockerfile(t *testing.T) {
	want := []string{"bun exact 1.4.4", "rust line 1.96", "unresolved ${REGISTRY}/acme/base:1", "bun exact 1.4.4", "debian line 12"}
	if got := rows(Dockerfile(dockerfile)); !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
}

const compose = `services:
  db:
    image: postgres:16-alpine
    ports: ["5470:5432"]
  cache:
    image: "redis:7-alpine"   # sessions
  search:
    image: getmeili/meilisearch:latest
  mail:
    image: axllent/mailpit:latest
  pg:
    image: postgres:${PG_VERSION:-17.2}
  other:
    image: postgres:${PG_TAG}
  app:
    build: .
`

func TestCompose(t *testing.T) {
	want := []string{"postgresql line 16", "redis line 7", "meilisearch unpinned ", "- exact ", "postgresql exact 17.2", "unresolved postgres:${PG_TAG}"}
	got := rows(Compose(compose))
	if !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
}

const workflow = `jobs:
  test:
    strategy:
      matrix:
        node-version: [18.x, 20, "22"]
    steps:
      - uses: oven-sh/setup-bun@v2
        with: { bun-version: 1.4.4 }
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - uses: actions/setup-go@v5
        with:
          go-version: 1.24
          go-version-file: go.mod
      - uses: actions/setup-python@v5
        with:
          python-version:
            - "3.11"
            - 3.12
          cache: pip
      - uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
      - uses: oven-sh/setup-bun@v2
        with:
          bun-version: latest
`

func TestWorkflow(t *testing.T) {
	want := []string{"node line 18", "node line 20", "node line 22", "bun exact 1.4.4", "node line 20", "go line 1.24",
		"python line 3.11", "python line 3.12", "unresolved php-version: ${{ matrix.php }}", "bun unpinned "}
	if got := rows(Workflow(workflow)); !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
}

var lines = map[string][]Release{
	"postgresql": {{"17", "2029-11-08", "17.12", ""}, {"16", "2028-11-09", "16.16", ""}, {"13", "2025-11-13", "13.23", ""}, {"12", "2024-11-14", "12.22", ""}},
	"redis":      {{"8.10", "", "8.10.3", ""}, {"7.4", "", "7.4.9", ""}, {"7.2", "2025-02-28", "7.2.12", ""}},
	"debian":     {{"13", "2030-06-30", "13.7", ""}, {"12", "2028-06-30", "12.15", ""}, {"10", "2024-06-30", "10.13", ""}},
}

func TestJudge(t *testing.T) {
	const today = "2026-11-16"
	for raw, want := range map[string]struct{ status, reason, fix string }{
		"postgres:16.4":      {core.Unknown, ReasonNoAdvisory, "16.16"},
		"postgres:16.16":     {core.Unknown, ReasonNoAdvisory, ""},
		"postgres:16-alpine": {core.Unknown, ReasonNotExact, ""},
		"postgres:13.1":      {core.Unsupported, "", "16.16"},
		"postgres:12":        {core.Unsupported, "", "16.16"},
		"postgres:latest":    {core.Unknown, ReasonUnpinned, ""},
		"postgres:9":         {core.Unknown, ReasonNotListed, ""},
		"redis:7-alpine":     {core.Unknown, ReasonNotExact, ""}, // 7 floats to 7.4, which lives
		"redis:7.2.4":        {core.Unsupported, "", "7.4.9"},
		"redis:7.4.1":        {core.Unknown, ReasonNoAdvisory, "7.4.9"},
		"debian:bookworm":    {core.Unknown, ReasonDistro, ""},
		"debian:buster":      {core.Unsupported, "", "12.15"},
		"mongo:7":            {core.Unknown, ReasonNoLines, ""},
	} {
		v, how := Judge(ParseRef(raw), lines, today)
		reason, fix := "", ""
		if v.Reason != nil {
			reason = *v.Reason
		}
		if v.Fix != nil {
			fix = *v.Fix
		}
		if v.Status != want.status || reason != want.reason || fix != want.fix || (v.Status != core.Unknown && how == "") {
			t.Errorf("%s: %s %q fix %q how %q, want %+v", raw, v.Status, reason, fix, how, want)
		}
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"16.4", "16.16", -1}, {"16", "16.0", 0}, {"24.8.4.13", "24.8", 1}, {"3.19", "3.2", 1}} {
		if got := compare(c.a, c.b); got != c.want {
			t.Errorf("%s %s: %d", c.a, c.b, got)
		}
	}
}
