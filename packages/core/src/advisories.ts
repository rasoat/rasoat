// Pure functions over GitHub Advisory Database records for the `next` npm package.
// Source: https://docs.github.com/en/rest/security-advisories/global-advisories (data: CC-BY-4.0).

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export interface Range {
  vulnerable: string; // as published, e.g. ">= 13.0.0, < 15.5.16"
  patched: string | null; // first_patched_version
}

export interface Advisory {
  ghsa: string;
  cve: string | null;
  severity: Severity;
  cvss: number | null;
  cwes: string[];
  summary: string; // English, from the advisory (CC-BY-4.0)
  published: string; // YYYY-MM-DD
  updated: string; // YYYY-MM-DD
  url: string; // https://github.com/advisories/GHSA-…
  ranges: Range[];
}

/** Scope of the page: advisories that touch any version from this one on. */
export const SCOPE_FROM = "13.0.0";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];

/** Keep only what the page needs. Credits (people's names) are dropped on purpose. */
export function normalize(raw: any): Advisory {
  const severity = SEVERITIES.includes(raw.severity) ? raw.severity : "unknown";
  return {
    ghsa: raw.ghsa_id,
    cve: raw.cve_id ?? null,
    severity,
    cvss: raw.cvss_severities?.cvss_v4?.score || raw.cvss_severities?.cvss_v3?.score || raw.cvss?.score || null,
    cwes: (raw.cwes ?? []).map((c: any) => c.cwe_id),
    summary: raw.summary,
    published: raw.published_at.slice(0, 10),
    updated: raw.updated_at.slice(0, 10),
    url: raw.html_url,
    ranges: (raw.vulnerabilities ?? [])
      .filter((v: any) => v.package?.ecosystem === "npm" && v.package?.name === "next")
      .map((v: any) => ({ vulnerable: v.vulnerable_version_range, patched: v.first_patched_version ?? null })),
  };
}

/** GHSA range syntax (">= 1.0.0, < 2.0.0", "= 12.3.5") → Bun.semver syntax. */
export function toSemver(range: string): string {
  return range.split(",").map((part) => part.replace(/\s+/g, "")).join(" ");
}

export function isVulnerable(version: string, adv: Advisory): boolean {
  return adv.ranges.some((r) => Bun.semver.satisfies(version, toSemver(r.vulnerable)));
}

/** True when the range's upper end reaches SCOPE_FROM (or has no upper end). */
export function rangeReaches(range: string, from = SCOPE_FROM): boolean {
  const parts = range.split(",").map((p) => p.trim());
  const upper = parts.find((p) => p.startsWith("<") || p.startsWith("="));
  if (!upper) return true;
  const op = upper.match(/^(<=|<|=)/)![1];
  const v = upper.slice(op.length).trim();
  const order = Bun.semver.order(v, from);
  return op === "<" ? order > 0 : order >= 0;
}

export function inScope(adv: Advisory): boolean {
  return adv.ranges.some((r) => rangeReaches(r.vulnerable));
}

const byVersion = (a: string, b: string) => Bun.semver.order(a, b);
const isStable = (v: string) => !v.includes("-");

export interface LineStatus {
  major: number;
  newestPatched: string; // highest stable patched version published for this major
  open: Advisory[]; // advisories that still affect newestPatched
}

/**
 * For each major from 13 on: the newest stable version any advisory names as a fix,
 * and the advisories that version is still exposed to (no fix on that line).
 */
export function lineStatus(advisories: Advisory[]): LineStatus[] {
  const patched = advisories.flatMap((a) => a.ranges.map((r) => r.patched)).filter((v): v is string => !!v && isStable(v));
  const majors = [...new Set(patched.map((v) => Number(v.split(".")[0])))].filter((m) => m >= 13).sort((a, b) => a - b);
  return majors.map((major) => {
    const newestPatched = patched.filter((v) => v.startsWith(`${major}.`)).sort(byVersion).at(-1)!;
    return { major, newestPatched, open: advisories.filter((a) => isVulnerable(newestPatched, a)) };
  });
}

/** What a reader typed, made comparable: trimmed, a leading "v" dropped. Null when it is not a full x.y.z[-pre] version. */
export function parseVersion(input: string): string | null {
  const v = input.trim().replace(/^v/i, "");
  return v.length <= 40 && /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(v) ? v : null;
}

export interface Check {
  version: string;
  hits: Advisory[]; // advisories whose published range contains `version`
  fix: string | null; // lowest version reached by following each hit's fix that no advisory hits; null if a hit has no fix
}

/**
 * Prerelease versions follow npm semver rules, as the advisory ranges do: a canary is hit only by ranges
 * that name canaries of the same x.y.z.
 */
export function checkVersion(version: string, advisories: Advisory[]): Check {
  const hitsOf = (v: string) => advisories.filter((a) => isVulnerable(v, a));
  const hits = hitsOf(version);
  let fix: string | null = version;
  for (let open = hits, guard = 0; fix && open.length && guard++ < 50; ) {
    const at: string = fix;
    const next = open.map((a) => a.ranges.find((r) => Bun.semver.satisfies(at, toSemver(r.vulnerable)))!.patched);
    fix = next.includes(null) ? null : (next as string[]).sort(byVersion).at(-1)!;
    if (fix) open = hitsOf(fix);
  }
  return { version, hits, fix: hits.length ? fix : null };
}
