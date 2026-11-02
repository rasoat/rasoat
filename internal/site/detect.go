package site

import (
	"github.com/rasoat/rasoat/internal/core"
	"sort"
	"strings"
)

// Finding is one framework on the page. Version empty: seen, but its version is not visible.
type Finding struct {
	Framework string
	Version   string
	How       string
	Where     string
}

const nextV = `(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)`

// Strongest first. Each was read off a known-version build. Each is anchored on a Next-only neighbour, so React's own
// `t.version="18.2.0"` never matches.
var nextPatterns = []struct {
	how string
	re  *core.Re
}{
	{"window.next.version", core.NewRe(`window\.next=\{version:"` + nextV + `"`)},
	{"pages-router main chunk", core.NewRe(`[\w$]+="` + nextV + `",[\w$]+=\(0,[\w$]+\.default\)\(\)`)},
	{"pages-router main chunk", core.NewRe(`[\w$]+\.version="` + nextV + `",[\w$]+\.router=`)},
	{"pages-router main chunk", core.NewRe(`window\.__NEXT_DATA__=[\w$]+;[\w$]+\.version="` + nextV + `"`)},
	{"next@ package path", core.NewRe(`node_modules/(?:\.pnpm/)?next@` + nextV)},
}

var poweredNext = core.NewRe(`(?i)next\.js`)

func detectNext(c *Crawl) *Finding {
	seen := poweredNext.MatchString(c.Page.Headers["x-powered-by"]) ||
		strings.Contains(c.Page.Body, "/_next/static/") || strings.Contains(c.Page.Body, "__NEXT_DATA__") || strings.Contains(c.Page.Body, "self.__next_f")
	for h := range c.Page.Headers {
		seen = seen || strings.HasPrefix(h, "x-nextjs-")
	}
	if !seen {
		return nil
	}
	for _, p := range nextPatterns {
		for _, s := range append([]*Resp{c.Page}, c.Scripts...) {
			if m := p.re.FindStringSubmatch(s.Body); m != nil {
				return &Finding{"next", m[1], p.how, s.URL}
			}
		}
	}
	return &Finding{Framework: "next"}
}

const wpV = `(\d+\.\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)` // a dev build: 7.2-alpha-61234

var (
	// Core assets WordPress enqueues with its own version as ?ver= (theme and plugin assets carry their own).
	coreAsset = core.NewRe(`/wp-includes/(?:css/dist/block-library/style|css/dashicons|js/wp-emoji-release|js/comment-reply|js/wp-embed)[^"'\s?]*\?ver=` + wpV + `["'&\s\\]`)
	generator = core.NewRe(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress ` + wpV)
	restLink  = core.NewRe(`<link[^>]+rel=["']https://api\.w\.org/["']`)
	feedGen   = core.NewRe(`<generator>https?://wordpress\.org/\?v=` + wpV + `</generator>`)
)

func detectWordPress(c *Crawl) *Finding {
	html := c.Page.Body
	gen := generator.FindStringSubmatch(html)
	if !strings.Contains(html, "/wp-content/") && !strings.Contains(html, "/wp-includes/") && !restLink.MatchString(html) &&
		!strings.Contains(c.Page.Headers["link"], "api.w.org") && gen == nil {
		return nil
	}
	if gen != nil {
		return &Finding{"wordpress", gen[1], "generator meta", c.Page.URL}
	}
	// Core asset ?ver=: take the value most core assets agree on.
	votes := map[string]int{}
	var order []string
	for _, m := range coreAsset.FindAllStringSubmatch(strings.ReplaceAll(html, `\/`, "/"), -1) {
		if votes[m[1]] == 0 {
			order = append(order, m[1])
		}
		votes[m[1]]++
	}
	sort.SliceStable(order, func(i, j int) bool { return votes[order[i]] > votes[order[j]] })
	if len(order) > 0 {
		return &Finding{"wordpress", order[0], "core asset ?ver=", c.Page.URL}
	}
	if c.Feed != nil {
		if m := feedGen.FindStringSubmatch(c.Feed.Body); m != nil {
			return &Finding{"wordpress", m[1], "RSS feed generator", c.Feed.URL}
		}
	}
	return &Finding{Framework: "wordpress"}
}

func detect(c *Crawl) []Finding {
	out := []Finding{}
	for _, f := range []*Finding{detectNext(c), detectWordPress(c)} {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}
