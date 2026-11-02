package site

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPublicAddresses(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false, "169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false,
		"::1": false, "fe80::1": false, "fc00::1": false, "::ffff:127.0.0.1": false, "::ffff:8.8.8.8": true, "2001:db8::1": false, "2002:7f00::1": false, "224.0.0.1": false,
	} {
		if got := IsPublicAddress(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s = %v", ip, got)
		}
	}
}

func TestScriptOrder(t *testing.T) {
	html := `<script src="/_next/static/a.js"></script><link rel="preload" as="script" href="/_next/static/p.js"><script src="/_next/static/chunks/main-x.js"></script><script src="https://cdn.example/o.js"></script>`
	got := ScriptURLs(html, "https://s.example/page")
	want := []string{"https://s.example/_next/static/chunks/main-x.js", "https://s.example/_next/static/a.js", "https://s.example/_next/static/p.js", "https://cdn.example/o.js"}
	if !slices.Equal(got, want) {
		t.Error(got)
	}
}

func TestFeedOnlyForWordPress(t *testing.T) {
	link := `<link rel="alternate" type="application/rss+xml" href="/feed/">`
	if FeedURL(link, "https://s.example/") != "" {
		t.Error("no WordPress sign")
	}
	if got := FeedURL(link+`<a href="/wp-content/x">`, "https://s.example/"); got != "https://s.example/feed/" {
		t.Error(got)
	}
}
