package site

import (
	"github.com/rasoat/rasoat/internal/core"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Crawl is a page, the scripts it loads, and for WordPress the RSS feed it links.
type Crawl struct {
	Page    *Resp
	Scripts []*Resp
	Feed    *Resp
}

var (
	linkTag   = core.NewRe(`(?i)<link\b[^>]*`)
	rssType   = core.NewRe(`(?i)\btype=["']application/rss\+xml["']`)
	asScript  = core.NewRe(`(?i)\bas=["']script["']`)
	hrefAttr  = core.NewRe(`(?i)\bhref=["']([^"']+)["']`)
	scriptTag = core.NewRe(`(?i)<script\b[^>]*?\bsrc=["']([^"']+)["']`)
	wpAsset   = core.NewRe(`/wp-(?:content|includes)/`)
	// Where Next.js keeps its version: the client bootstrap. A page can list 60+ chunks, so these go first.
	bootstrap = core.NewRe(`/chunks/(?:main|main-app|webpack|framework|polyfills)[-.]|/chunks/pages/_app[-.]|/turbopack-`)
	mainChunk = core.NewRe(`/chunks/main-`)
	waitsFor  = core.NewRe(`\.O\(0,\[([\d,]+)\]`)
)

func resolve(ref, base string) (string, bool) {
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	u, err := b.Parse(strings.ReplaceAll(ref, "&amp;", "&"))
	if err != nil {
		return "", false
	}
	return u.String(), true
}

// FeedURL is the first RSS feed a WordPress page links to: a public URL the page itself advertises.
func FeedURL(html, base string) string {
	if !wpAsset.MatchString(html) {
		return ""
	}
	for _, tag := range linkTag.FindAllString(html, -1) {
		if rssType.MatchString(tag) {
			if m := hrefAttr.FindStringSubmatch(tag); m != nil {
				u, _ := resolve(m[1], base)
				return u
			}
		}
	}
	return ""
}

// ScriptURLs lists what a page loads, absolute and de-duplicated, in fetch order: bootstrap chunks, Next's script tags in
// document order, its preloads, then everything else.
func ScriptURLs(html, base string) []string {
	rank := map[string]int{}
	var order []string
	add := func(src string, preload bool) {
		u, ok := resolve(src, base)
		if !ok {
			return
		}
		r := 3
		switch {
		case bootstrap.MatchString(u):
			r = 0
		case !strings.Contains(u, "/_next/"):
			r = 3
		case preload:
			r = 2
		default:
			r = 1
		}
		if old, seen := rank[u]; !seen {
			order = append(order, u)
			rank[u] = r
		} else if old > r {
			rank[u] = r
		}
	}
	for _, m := range scriptTag.FindAllStringSubmatch(html, -1) {
		add(m[1], false)
	}
	for _, tag := range linkTag.FindAllString(html, -1) {
		if asScript.MatchString(tag) {
			if m := hrefAttr.FindStringSubmatch(tag); m != nil {
				add(m[1], true)
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return rank[order[i]] < rank[order[j]] })
	return order
}

func fetchAll(urls []string, get Get) []*Resp {
	var out []*Resp
	for i := 0; i < len(urls); i += 6 {
		batch := urls[i:min(i+6, len(urls))]
		got := make([]*Resp, len(batch))
		var wg sync.WaitGroup
		for j, u := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if r, err := get(u); err == nil && r.Status == 200 {
					got[j] = r
				}
			}()
		}
		wg.Wait()
		for _, r := range got {
			if r != nil {
				out = append(out, r)
			}
		}
	}
	return out
}

func crawl(target string, get Get, maxScripts int) (*Crawl, error) {
	page, err := get(target)
	if err != nil {
		return nil, err
	}
	all := ScriptURLs(page.Body, page.URL)
	scripts := fetchAll(all[:min(maxScripts, len(all))], get)
	// Custom splitChunks can leave `main` a stub that only waits for other chunks, and the version sits in one of those.
	// Fetch them even past the cap: at most a few.
	fetched := map[string]bool{}
	var deps []string
	for _, s := range scripts {
		fetched[s.URL] = true
		if mainChunk.MatchString(s.URL) {
			if m := waitsFor.FindStringSubmatch(s.Body); m != nil {
				deps = append(deps, strings.Split(m[1], ",")...)
			}
		}
	}
	var extra []string
	for _, u := range all {
		if fetched[u] || len(extra) == 4 {
			continue
		}
		for _, id := range deps {
			if strings.Contains(u, "/chunks/"+id+"-") || strings.Contains(u, "/chunks/"+id+".") {
				extra = append(extra, u)
				break
			}
		}
	}
	scripts = append(scripts, fetchAll(extra, get)...)
	c := &Crawl{Page: page, Scripts: scripts}
	if at := FeedURL(page.Body, page.URL); at != "" {
		if r, err := get(at); err == nil && r.Status == 200 {
			c.Feed = r
		}
	}
	return c, nil
}
