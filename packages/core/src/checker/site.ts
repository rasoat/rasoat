// One site, from address to findings: crawl → detect → runtimes, and what to call the failures. The site checker and
// the CLI both answer from this; only their `get` differs.
import { crawl, type Get } from "./crawl.ts";
import { detect, type Finding } from "./detect.ts";
import { inferRuntimes, type FrameworkRuntimes, type RuntimeFinding } from "./runtime.ts";
import type { RtData, RuntimeId } from "../runtimes.ts";

export type SiteOutcome =
  | { kind: "unreachable"; status: number | null; cause?: "timeout" | "tls" | "network" }
  | { kind: "blocked"; status: number; by: string | null } // bot protection answered instead of the site
  | { kind: "result"; url: string; findings: Finding[]; runtimes: RuntimeFinding[]; tlsUnverified: boolean };

/** Statuses a WAF or bot wall answers with. We report them; we never try to get past them. */
const BLOCKED = new Set([401, 403, 429, 503]);
const blocker = (h: Record<string, string>) =>
  h["cf-mitigated"] || /cloudflare/i.test(h.server ?? "") ? "Cloudflare" : /akamai/i.test(h.server ?? "") || h["akamai-grn"] ? "Akamai" : null;

/** Throws what `get` throws; `unreachableFrom` names it unless the caller has its own meaning for it. */
export async function inspectSite(target: string, get: Get, data: { requirements: FrameworkRuntimes; runtimes: Partial<Record<RuntimeId, RtData>> }, maxScripts = 30): Promise<SiteOutcome> {
  const c = await crawl(target, get, maxScripts);
  const { page } = c;
  if (BLOCKED.has(page.status)) return { kind: "blocked", status: page.status, by: blocker(page.headers) };
  if (page.status >= 400) return { kind: "unreachable", status: page.status };
  const findings = detect(c);
  return { kind: "result", url: page.url, findings, runtimes: inferRuntimes(c, findings, data.requirements, data.runtimes), tlsUnverified: !!page.tlsUnverified };
}

export function unreachableFrom(e: unknown): SiteOutcome {
  const err = e as { name?: string; code?: string };
  const cause = err.name === "TimeoutError" || err.code === "ABORT_ERR" ? "timeout" : /CERT|SSL|TLS/i.test(err.code ?? "") ? "tls" : "network";
  return { kind: "unreachable", status: null, cause };
}
