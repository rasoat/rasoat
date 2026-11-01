// WordPress core: which CVEs reach a version, and what WordPress.org says about it.
// Data: data/wordpress-core.json (scripts/wordpress/fetch.ts) — NVD CVEs (per-branch ranges) + WordPress.org stable-check.
import type { Severity } from "./advisories.ts";

export interface WpRange {
  start: string | null; // inclusive
  end: string;
  endIncluding: boolean;
}

export interface WpCve {
  cve: string;
  severity: Severity;
  cvss: number | null;
  summary: string; // English, from NVD
  published: string; // YYYY-MM-DD
  url: string; // https://nvd.nist.gov/vuln/detail/CVE-…
  ranges: WpRange[];
}

export type WpStatus = "latest" | "outdated" | "insecure";

export interface WpData {
  fetched: string;
  stable: Record<string, WpStatus>; // WordPress.org stable-check: every release
  cves: WpCve[];
}

/** WordPress versions are 2–4 numeric parts ("6.4", "4.1.40", "1.5.1.1"): compare part by part, missing = 0. */
export function compareWp(a: string, b: string): number {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export const isWpVersion = (v: string) => /^\d+\.\d+(\.\d+){0,2}$/.test(v);

export function inWpRange(v: string, r: WpRange): boolean {
  if (r.start && compareWp(v, r.start) < 0) return false;
  const c = compareWp(v, r.end);
  return r.endIncluding ? c <= 0 : c < 0;
}

const branch = (v: string) => v.split(".").slice(0, 2).join(".");

export interface WpCheck {
  version: string;
  status: WpStatus | "unknown"; // WordPress.org's word; unknown = not a release it lists
  /**
   * NVD CVEs whose range contains the version, most severe first — only when WordPress.org does not call the release
   * patched. Measured 2026-10-31: older NVD ranges ("before 5.5.2") ignore backports, so 14 patched branch heads
   * (4.7.39 … 6.0.18) would show 2–73 false hits; and NVD lags recent fixes (6.9.10: insecure, 0 ranged CVEs).
   * WordPress.org's status is therefore the verdict; the CVE list is supporting detail.
   */
  hits: WpCve[];
  fix: string | null; // newest patched release on the same branch, else the latest; null when already patched
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

export function checkWordPress(version: string, data: WpData): WpCheck {
  const release = version.replace(/-.*$/, ""); // 7.2-alpha-61234 → 7.2 for comparisons; never a WordPress.org release
  const status = version !== release ? "unknown" : (data.stable[version] ?? data.stable[version.replace(/\.0$/, "")] ?? "unknown");
  const patchedRelease = status === "latest" || status === "outdated";
  const hits = data.cves
    .filter((c) => !patchedRelease && c.ranges.some((r) => inWpRange(release, r)))
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || (b.cvss ?? 0) - (a.cvss ?? 0));
  const patched = Object.entries(data.stable).filter(([, s]) => s !== "insecure").map(([v]) => v);
  const latest = patched.find((v) => data.stable[v] === "latest") ?? null;
  const sameBranch = patched.filter((v) => branch(v) === branch(release)).sort(compareWp).at(-1) ?? null;
  const newerThanLatest = !!latest && compareWp(release, latest) > 0; // a dev build ahead of the latest release
  const fix = patchedRelease || newerThanLatest ? null : sameBranch && compareWp(sameBranch, release) > 0 ? sameBranch : latest;
  return { version, status, hits, fix };
}
