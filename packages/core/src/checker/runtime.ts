// The runtime behind a checked site: exact when a response header names it, otherwise bounded by what the detected
// framework version requires, plus an era estimate from that version's release date (labelled as an estimate).
import type { Crawl } from "./crawl.ts";
import type { Finding } from "./detect.ts";
import { normalizeRuntime, type RtData, type RuntimeId } from "../runtimes.ts";

export interface FrameworkRuntimes {
  next: { v: string; date: string; node: string }[]; // stable versions, oldest first
  wordpress: Record<string, string>; // branch → minimum PHP
}

export interface RuntimeFinding {
  runtime: RuntimeId;
  version: string | null; // exact, from a header
  how: string | null; // the header it came from
  /** Lower bound the framework imposes (a fact from its package metadata). */
  min: { version: string; framework: string; frameworkVersion: string } | null;
  /** Runtime lines current when the framework version shipped — an estimate, never a finding. */
  era: { date: string; lines: { cycle: string; eol: string | null }[] } | null;
}

const PHP_IN = /\bPHP\/(\d+\.\d+(?:\.\d+)?)/i;

/** Runtimes named by response headers. Only PHP usually states a version; Node/Bun appear through their servers. */
export function headerRuntimes({ page }: Crawl): RuntimeFinding[] {
  const h = page.headers;
  const said = `${h["x-powered-by"] ?? ""} ${h.server ?? ""}`;
  const out: RuntimeFinding[] = [];
  const php = said.match(PHP_IN);
  if (php) out.push({ runtime: "php", version: normalizeRuntime(php[1]!), how: h["x-powered-by"]?.match(PHP_IN) ? "X-Powered-By" : "Server", min: null, era: null });
  else if (/\bPHP\b/i.test(said)) out.push({ runtime: "php", version: null, how: "X-Powered-By", min: null, era: null });
  if (/\bBun\b/i.test(said)) out.push({ runtime: "bun", version: said.match(/\bBun\/(\d+\.\d+\.\d+)/i)?.[1] ?? null, how: "Server", min: null, era: null });
  else if (/\b(Express|Next\.js|Nuxt|Koa|Fastify|NestJS)\b/i.test(h["x-powered-by"] ?? "")) out.push({ runtime: "node", version: null, how: "X-Powered-By", min: null, era: null });
  return out;
}

/** Smallest version an engines range admits: "^18.18.0 || ^19.8.0 || >= 20.0.0" → 18.18.0. */
export function minOfRange(range: string): string | null {
  const vs = [...range.matchAll(/(\d+\.\d+\.\d+|\d+\.\d+|\d+)/g)].map((m) => normalizeRuntime(m[1]!.split(".").length === 1 ? `${m[1]}.0` : m[1]!)!);
  return vs.sort((a, b) => Bun.semver.order(a, b))[0] ?? null;
}

/** Lines of `rt` that existed and were not yet end-of-life on `date`, from `min`'s line on. */
function eraLines(rt: RtData, date: string, min: string) {
  const minCycle = Number(min.split(".")[0]);
  return rt.branches
    .filter((b) => b.released <= date && (!b.eol || b.eol >= date) && Number(b.cycle.split(".")[0]) >= minCycle)
    .map((b) => ({ cycle: b.cycle, eol: b.eol }))
    .reverse(); // oldest first
}

export function inferRuntimes(crawl: Crawl, findings: Finding[], req: FrameworkRuntimes, runtimes: Partial<Record<RuntimeId, RtData>>): RuntimeFinding[] {
  const found = headerRuntimes(crawl);
  const next = findings.find((f) => f.framework === "next" && f.version);
  if (next && !found.some((r) => r.runtime === "bun")) {
    const base = next.version!.replace(/-.*$/, "");
    const row = [...req.next].reverse().find((r) => Bun.semver.order(r.v, base) <= 0); // this release or the closest before
    const min = row ? minOfRange(row.node) : null;
    if (row && min) {
      const node = found.find((r) => r.runtime === "node") ?? { runtime: "node" as const, version: null, how: null, min: null, era: null };
      node.min = { version: min, framework: "Next.js", frameworkVersion: next.version! };
      if (runtimes.node) node.era = { date: row.date, lines: eraLines(runtimes.node, row.date, min) };
      if (!found.includes(node)) found.push(node);
    }
  }
  const wp = findings.find((f) => f.framework === "wordpress" && f.version);
  if (wp) {
    const php = found.find((r) => r.runtime === "php");
    const need = req.wordpress[wp.version!.split(".").slice(0, 2).join(".")];
    if (need && !php?.version) {
      const r = php ?? { runtime: "php" as const, version: null, how: null, min: null, era: null };
      r.min = { version: normalizeRuntime(need)!, framework: "WordPress", frameworkVersion: wp.version! };
      if (!php) found.push(r);
    }
  }
  return found;
}
