// Next.js: identified from what any visitor's browser downloads (page + scripts).
// Patterns come from real builds: scripts/checker/fixtures/ (10.2 → 16.4, App and Pages Router, webpack and Turbopack).
import type { Framework } from "../detect.ts";

const V = String.raw`(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)`;

/** Strongest first. Each was read off a known-version build (see find-version.ts). */
const VERSION_PATTERNS: { how: string; re: RegExp }[] = [
  // App Router bootstrap: window.next={version:"15.5.28",appDir:!0}
  { how: "window.next.version", re: new RegExp(String.raw`window\.next=\{version:"${V}"`) },
  // Pages Router client (main chunk), three generations. Each is anchored on a Next-only neighbour, so React's own
  // `t.version="18.2.0"` never matches.
  // 13.4+: let G="15.1.0",X=(0,E.default)()
  { how: "pages-router main chunk", re: new RegExp(String.raw`[\w$]+="${V}",[\w$]+=\(0,[\w$]+\.default\)\(\)`) },
  // 12.0–13.3: t.version="13.1.6",t.router=n
  { how: "pages-router main chunk", re: new RegExp(String.raw`[\w$]+\.version="${V}",[\w$]+\.router=`) },
  // 10–11: window.__NEXT_DATA__=A;t.version="10.2.3"
  { how: "pages-router main chunk", re: new RegExp(String.raw`window\.__NEXT_DATA__=[\w$]+;[\w$]+\.version="${V}"`) },
  // Bundler path left in a chunk: node_modules/.pnpm/next@16.5.0-canary.25_…
  { how: "next@ package path", re: new RegExp(String.raw`node_modules/(?:\.pnpm/)?next@${V}`) },
];

export const next: Framework = {
  id: "next",
  detect({ page, scripts }) {
    const signals: string[] = [];
    const powered = page.headers["x-powered-by"] ?? "";
    if (/next\.js/i.test(powered)) signals.push(`x-powered-by: ${powered}`);
    if (Object.keys(page.headers).some((h) => h.startsWith("x-nextjs-"))) signals.push("x-nextjs-* header");
    if (page.body.includes("/_next/static/")) signals.push("/_next/static/ assets");
    if (page.body.includes("__NEXT_DATA__")) signals.push("__NEXT_DATA__ (Pages Router)");
    if (page.body.includes("self.__next_f")) signals.push("self.__next_f (App Router)");
    if (signals.length === 0) return null;
    for (const { how, re } of VERSION_PATTERNS) {
      for (const s of [page, ...scripts]) {
        const m = s.body.match(re);
        if (m) return { framework: "next", version: m[1]!, how, where: s.url, signals };
      }
    }
    return { framework: "next", version: null, how: null, where: null, signals };
  },
};
