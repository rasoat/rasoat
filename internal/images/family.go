// Package images reads the container images and CI runtime pins a project names, and judges the families whose
// release lines are known. Text only: nothing is pulled and nothing runs.
package images

import (
	"sort"
	"strings"
)

// Family is one product an image or a CI pin names. ID is the endoflife.date product id, which is also the product
// string of a report row (the four products the CLI already judges keep their own: node, bun, php, wordpress).
type Family struct {
	ID         string
	Name       string
	Core       bool              // judged by core.VerdictFor from a pin, as a .nvmrc is
	Distro     bool              // the release is the identity: its packages move under one tag, so a tag is never "exact"
	PgTag      bool              // an image built on PostgreSQL: the tag names the PostgreSQL major as pgNN
	Codenames  map[string]string // release name to cycle
	ExactParts int               // numeric parts of a tag that name one release; default 3
}

var debian = map[string]string{"stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
var ubuntu = map[string]string{"bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04", "oracular": "24.10", "plucky": "25.04", "questing": "25.10"}

// The one family table. A key is an image name without registry or `library/`.
var byImage = map[string]*Family{}

// byID is every family by id, for CI pins and display names.
var byID = map[string]*Family{}

func add(f Family, images ...string) *Family {
	if f.ExactParts == 0 {
		f.ExactParts = 3
	}
	byID[f.ID] = &f
	for _, i := range images {
		byImage[i] = &f
	}
	return &f
}

// pgWrapped is the PostgreSQL family reached through another project's image.
var pgWrapped *Family

func init() {
	add(Family{ID: "node", Name: "Node.js", Core: true}, "node")
	add(Family{ID: "bun", Name: "Bun", Core: true}, "oven/bun")
	add(Family{ID: "php", Name: "PHP", Core: true}, "php")
	add(Family{ID: "wordpress", Name: "WordPress", Core: true}, "wordpress")
	add(Family{ID: "postgresql", Name: "PostgreSQL", ExactParts: 2}, "postgres")
	w := *byID["postgresql"]
	w.PgTag = true
	pgWrapped = &w
	for _, i := range []string{"pgvector/pgvector", "timescale/timescaledb", "timescale/timescaledb-ha"} {
		byImage[i] = pgWrapped
	}
	add(Family{ID: "redis", Name: "Redis"}, "redis")
	add(Family{ID: "nginx", Name: "nginx"}, "nginx")
	add(Family{ID: "mariadb", Name: "MariaDB"}, "mariadb")
	add(Family{ID: "mysql", Name: "MySQL"}, "mysql")
	add(Family{ID: "clickhouse", Name: "ClickHouse"}, "clickhouse/clickhouse-server")
	add(Family{ID: "caddy", Name: "Caddy"}, "caddy")
	add(Family{ID: "debian", Name: "Debian", Distro: true, Codenames: debian}, "debian")
	add(Family{ID: "ubuntu", Name: "Ubuntu", Distro: true, Codenames: ubuntu}, "ubuntu")
	add(Family{ID: "alpine-linux", Name: "Alpine Linux", Distro: true}, "alpine")
	add(Family{ID: "python", Name: "Python"}, "python")
	add(Family{ID: "go", Name: "Go"}, "golang")
	add(Family{ID: "rust", Name: "Rust"}, "rust")
	add(Family{ID: "grafana", Name: "Grafana"}, "grafana/grafana", "grafana/grafana-oss")
	add(Family{ID: "prometheus", Name: "Prometheus"}, "prom/prometheus")
	add(Family{ID: "meilisearch", Name: "Meilisearch"}, "getmeili/meilisearch")
	add(Family{ID: "traefik", Name: "Traefik"}, "traefik")
	add(Family{ID: "mongodb", Name: "MongoDB"}, "mongo")
	add(Family{ID: "rabbitmq", Name: "RabbitMQ"}, "rabbitmq")
}

// ciKeys maps a workflow's `<key>-version:` to a family id.
var ciKeys = map[string]string{"node": "node", "bun": "bun", "php": "php", "go": "go", "python": "python"}

// Products are the endoflife.date ids whose release lines the index must carry for this table, sorted.
func Products() []string {
	var out []string
	for id, f := range byID {
		if !f.Core {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// ByID is the family with this endoflife.date id, or nil.
func ByID(id string) *Family { return byID[id] }

// Name is a product's display name, or the id itself for one this table does not know.
func Name(id string) string {
	if f := byID[id]; f != nil {
		return f.Name
	}
	return id
}

func lookup(image string) *Family {
	if f := byImage[image]; f != nil {
		return f
	}
	if strings.HasPrefix(image, "tensorchord/") {
		return pgWrapped
	}
	return nil
}
