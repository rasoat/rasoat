// Fetch a page and the scripts it loads. Network access is injected (`Get`), so the web app can pass a guarded
// fetch and tests can replay a recording of a real site.

export interface Resp {
  url: string; // final URL after redirects
  status: number;
  headers: Record<string, string>; // lower-case names
  body: string;
  tlsUnverified?: boolean; // read although the HTTPS chain did not verify (see safe-get.ts)
}
export type Get = (url: string) => Promise<Resp>;

export interface Crawl {
  page: Resp;
  scripts: Resp[];
  feed?: Resp | null; // the RSS feed the page links, fetched only for WordPress pages (its <generator> names the version)
}

const FEED_LINK = /<link\b(?=[^>]*\btype=["']application\/rss\+xml["'])[^>]*?\bhref=["']([^"']+)["']/i;

/** The first RSS feed a WordPress page links to: a public URL the page itself advertises. */
export function feedUrl(html: string, base: string): string | null {
  if (!/\/wp-(?:content|includes)\//.test(html)) return null;
  const href = html.match(FEED_LINK)?.[1];
  if (!href) return null;
  try {
    return new URL(href.replace(/&amp;/g, "&"), base).href;
  } catch {
    return null;
  }
}

const SCRIPT_TAG = /<script\b[^>]*?\bsrc=["']([^"']+)["']/gi;
const PRELOAD = /<link\b(?=[^>]*\bas=["']script["'])[^>]*?\bhref=["']([^"']+)["']/gi;
/** Where Next.js keeps its version: the client bootstrap. A page can list 60+ chunks, so these go first. */
const BOOTSTRAP = /\/chunks\/(?:main|main-app|webpack|framework|polyfills)[-.]|\/chunks\/pages\/_app[-.]|\/turbopack-/;

/**
 * Script URLs a page loads, absolute and de-duplicated, in fetch order: bootstrap chunks, then Next's
 * <script src> in document order, then its preloads, then everything else.
 */
export function scriptUrls(html: string, base: string): string[] {
  const found = new Map<string, number>();
  const add = (src: string, preload: boolean) => {
    let url: string;
    try {
      url = new URL(src.replace(/&amp;/g, "&"), base).href;
    } catch {
      return;
    }
    const rank = BOOTSTRAP.test(url) ? 0 : !url.includes("/_next/") ? 3 : preload ? 2 : 1;
    if (!found.has(url) || found.get(url)! > rank) found.set(url, rank);
  };
  for (const m of html.matchAll(SCRIPT_TAG)) add(m[1]!, false);
  for (const m of html.matchAll(PRELOAD)) add(m[1]!, true);
  return [...found].sort((a, b) => a[1] - b[1]).map(([url]) => url); // sort is stable: document order within a rank
}

export async function crawl(url: string, get: Get, maxScripts = 40): Promise<Crawl> {
  const page = await get(url);
  const all = scriptUrls(page.body, page.url);
  const scripts = await fetchAll(all.slice(0, maxScripts), get);
  // Custom splitChunks can leave `main` a stub that only waits for other chunks — `n.O(0,[97270,46362],…)` — and
  // the version sits in one of those (phongvu.vn, 2026-10-31). Fetch them even past the cap: at most a few.
  const fetched = new Set(scripts.map((s) => s.url));
  const deps = scripts
    .filter((s) => /\/chunks\/main-/.test(s.url))
    .flatMap((s) => s.body.match(/\.O\(0,\[([\d,]+)\]/)?.[1]!.split(",") ?? []);
  const extra = all.filter((u) => !fetched.has(u) && deps.some((id) => new RegExp(`/chunks/${id}[-.]`).test(u))).slice(0, 4);
  scripts.push(...(await fetchAll(extra, get)));
  const feedAt = feedUrl(page.body, page.url);
  const feed = feedAt ? await get(feedAt).then((r) => (r.status === 200 ? r : null), () => null) : null;
  return { page, scripts, feed };
}

async function fetchAll(urls: string[], get: Get): Promise<Resp[]> {
  const out: Resp[] = [];
  for (let i = 0; i < urls.length; i += 6) {
    const batch = await Promise.all(urls.slice(i, i + 6).map((u) => get(u).catch(() => null)));
    for (const r of batch) if (r && r.status === 200) out.push(r);
  }
  return out;
}
