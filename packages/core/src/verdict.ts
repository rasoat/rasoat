// One answer for one product at one version, in one shape: what the CLI prints and what --json gives an agent.
import { checkVersion, parseVersion, type Severity } from "./advisories.ts";
import { checkRuntime, type RuntimeId } from "./runtimes.ts";
import type { Snapshot } from "./snapshot.ts";
import { checkWordPress, isWpVersion } from "./wordpress.ts";

export type Product = "next" | "wordpress" | RuntimeId;

export const PRODUCT_NAMES: Record<Product, string> = { next: "Next.js", wordpress: "WordPress", node: "Node.js", php: "PHP", bun: "Bun" };

/**
 * vulnerable: a published advisory reaches this version. unsupported: its line gets no more fixes.
 * ok: no advisory in this snapshot reaches it. unknown: we cannot say, and `reason` tells why.
 */
export type Status = "vulnerable" | "unsupported" | "ok" | "unknown";
export type UnknownReason = "version-not-exact" | "version-hidden" | "not-a-listed-release" | "line-not-listed";

export interface VerdictAdvisory {
  id: string;
  severity: Severity;
  cvss: number | null;
  summary: string;
  url: string;
}

export interface Verdict {
  product: Product;
  version: string | null;
  status: Status;
  fix: string | null; // the version to move to; null when none is needed or no published release clears it
  noFix: boolean; // vulnerable, and no published release clears every advisory
  reason: UnknownReason | null;
  advisories: VerdictAdvisory[];
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const worstFirst = (a: VerdictAdvisory, b: VerdictAdvisory) => RANK[a.severity] - RANK[b.severity] || (b.cvss ?? 0) - (a.cvss ?? 0);

const unknown = (product: Product, version: string | null, reason: UnknownReason): Verdict =>
  ({ product, version, status: "unknown", fix: null, noFix: false, reason, advisories: [] });

const exactRuntime = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

export function verdictFor(product: Product, version: string | null, data: Snapshot, today?: string): Verdict {
  if (version === null) return unknown(product, null, "version-hidden");
  if (product === "next") {
    const v = parseVersion(version);
    if (!v) return unknown(product, version, "version-not-exact");
    const c = checkVersion(v, data.next.advisories);
    const advisories = c.hits.map((a) => ({ id: a.ghsa, severity: a.severity, cvss: a.cvss, summary: a.summary, url: a.url })).sort(worstFirst);
    return { product, version: v, status: c.hits.length ? "vulnerable" : "ok", fix: c.fix, noFix: c.hits.length > 0 && !c.fix, reason: null, advisories };
  }
  if (product === "wordpress") {
    if (!isWpVersion(version.replace(/-.*$/, ""))) return unknown(product, version, "version-not-exact");
    const c = checkWordPress(version, data.wordpress);
    if (c.status === "unknown") return { ...unknown(product, version, "not-a-listed-release"), fix: c.fix };
    const advisories = c.hits.map((a) => ({ id: a.cve, severity: a.severity, cvss: a.cvss, summary: a.summary, url: a.url }));
    return c.status === "insecure"
      ? { product, version, status: "vulnerable", fix: c.fix, noFix: !c.fix, reason: null, advisories }
      : { product, version, status: "ok", fix: null, noFix: false, reason: null, advisories: [] };
  }
  if (!exactRuntime.test(version)) return unknown(product, version, "version-not-exact");
  const c = checkRuntime(product, version, data.runtimes[product], today);
  if (!c.branch) return unknown(product, version, "line-not-listed");
  const advisories = c.hits.map((a) => ({ id: a.id, severity: a.severity, cvss: a.cvss, summary: a.summary, url: a.url }));
  const status: Status = c.hits.length ? "vulnerable" : c.eol ? "unsupported" : "ok";
  return { product, version, status, fix: status === "ok" ? null : c.fix, noFix: status !== "ok" && !c.fix, reason: null, advisories };
}
