// WordPress core: identified from the page, its core assets and the RSS feed it links.
// Patterns come from real installs: scripts/checker/fixtures/wordpress/ (official wordpress:<version> images).
import type { Framework } from "../detect.ts";

const V = String.raw`(\d+\.\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)`; // a dev build: 7.2-alpha-61234
/** Core assets WordPress enqueues with its own version as ?ver= (theme/plugin assets carry their own). */
const CORE_ASSET = new RegExp(String.raw`/wp-includes/(?:css/dist/block-library/style|css/dashicons|js/wp-emoji-release|js/comment-reply|js/wp-embed)[^"'\s?]*\?ver=${V}(?=["'&\s\\])`, "g");

export const wordpress: Framework = {
  id: "wordpress",
  detect({ page, feed }) {
    const html = page.body;
    const signals: string[] = [];
    if (/\/wp-content\//.test(html)) signals.push("/wp-content/ assets");
    if (/\/wp-includes\//.test(html)) signals.push("/wp-includes/ assets");
    if (/<link[^>]+rel=["']https:\/\/api\.w\.org\/["']/.test(html) || (page.headers.link ?? "").includes("api.w.org")) signals.push("REST API link (api.w.org)");
    const generator = html.match(new RegExp(String.raw`<meta[^>]+name=["']generator["'][^>]+content=["']WordPress ${V}`, "i"))?.[1];
    if (generator) signals.push("generator meta");
    if (signals.length === 0) return null;

    if (generator) return { framework: "wordpress", version: generator, how: "generator meta", where: page.url, signals };
    // Core asset ?ver=: take the value most core assets agree on.
    const votes = new Map<string, number>();
    for (const m of html.replace(/\\\//g, "/").matchAll(CORE_ASSET)) votes.set(m[1]!, (votes.get(m[1]!) ?? 0) + 1);
    const asset = [...votes].sort((a, b) => b[1] - a[1])[0]?.[0];
    if (asset) return { framework: "wordpress", version: asset, how: "core asset ?ver=", where: page.url, signals };
    const fromFeed = feed?.body.match(new RegExp(String.raw`<generator>https?://wordpress\.org/\?v=${V}</generator>`))?.[1];
    if (fromFeed) return { framework: "wordpress", version: fromFeed, how: "RSS feed generator", where: feed!.url, signals };
    return { framework: "wordpress", version: null, how: null, where: null, signals };
  },
};
