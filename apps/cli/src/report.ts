// A scan's outcome as data: --json prints it as is, the terminal view renders it, and the exit code comes from it.
import { NOTICES, verdictFor, type Product, type SiteOutcome, type Snapshot, type Status, type Verdict } from "@rasoat/core";
import type { Loaded } from "./data.ts";
import type { Walked } from "./walk.ts";

export const VERSION = "0.2.1";
export const TOOL = "rasoat";

export interface Result extends Verdict {
  sources: string[]; // files relative to the scanned directory, or URLs
  how: string | null; // for a site: what the version was read from
}

export interface Report {
  schema: 1;
  tool: { name: string; version: string };
  target: { kind: "dir" | "url"; value: string };
  data: { built: string; origin: Loaded["origin"]; age_days: number; stale: boolean; problem: Loaded["problem"] };
  site: { outcome: Exclude<SiteOutcome["kind"], "result"> | "ok"; status: number | null; by: string | null; cause: string | null; tls_unverified: boolean } | null;
  results: Result[];
  summary: Record<Status, number>;
  notes: string[]; // machine words: binary-bun-lock, truncated, or `<runtime>-min:<version>`
  not_checked: string[];
  notices: string[];
  exit_code: 0 | 1 | 3;
}

/** A clean result covers only these products: said on every run, because "no findings" reads as "safe" otherwise. */
export const NOT_CHECKED = ["wordpress-plugins-themes", "other-dependencies", "other-frameworks"] as const;

/** 1 = act on it. 3 = no proof either way: nothing identified, or a version we cannot judge. 0 only when all is judged clean. */
function exitCode(summary: Record<Status, number>, total: number): Report["exit_code"] {
  if (summary.vulnerable + summary.unsupported > 0) return 1;
  return summary.unknown > 0 || total === 0 ? 3 : 0;
}

function assemble(target: Report["target"], data: Loaded, results: Result[], site: Report["site"], notes: string[]): Report {
  const summary: Record<Status, number> = { vulnerable: 0, unsupported: 0, ok: 0, unknown: 0 };
  for (const r of results) summary[r.status]++;
  const rank: Record<Status, number> = { vulnerable: 0, unsupported: 1, unknown: 2, ok: 3 };
  return {
    schema: 1,
    tool: { name: TOOL, version: VERSION },
    target,
    data: { built: data.snapshot.built, origin: data.origin, age_days: data.ageDays, stale: data.stale, problem: data.problem },
    site,
    results: [...results].sort((a, b) => rank[a.status] - rank[b.status]),
    summary,
    notes,
    not_checked: [...NOT_CHECKED],
    notices: NOTICES, // ours, not the download's: a snapshot only supplies data
    exit_code: exitCode(summary, results.length),
  };
}

export function dirReport(root: string, walked: Walked, data: Loaded): Report {
  const byPin = new Map<string, Result>();
  for (const f of walked.found) {
    const key = `${f.product} ${f.version}`;
    const r = byPin.get(key) ?? { ...verdictFor(f.product, f.version, data.snapshot), sources: [], how: null };
    if (!r.sources.includes(f.path)) r.sources.push(f.path);
    byPin.set(key, r);
  }
  return assemble({ kind: "dir", value: root }, data, [...byPin.values()], null, walked.notes);
}

const shortUrl = (u: string | null) => (u ?? "").slice(0, 200);

export function siteReport(url: string, outcome: SiteOutcome, data: Loaded): Report {
  const target = { kind: "url" as const, value: url };
  if (outcome.kind !== "result") {
    const site = { outcome: outcome.kind, status: outcome.status, by: outcome.kind === "blocked" ? outcome.by : null, cause: outcome.kind === "unreachable" ? outcome.cause ?? null : null, tls_unverified: false };
    return assemble(target, data, [], site, []);
  }
  const verdict = (product: Product, version: string | null, snapshot: Snapshot) => verdictFor(product, version, snapshot);
  const results: Result[] = outcome.findings.map((f) => ({ ...verdict(f.framework, f.version, data.snapshot), sources: [shortUrl(f.where ?? outcome.url)], how: f.how }));
  const notes: string[] = [];
  for (const r of outcome.runtimes) {
    if (r.version) results.push({ ...verdict(r.runtime, r.version, data.snapshot), sources: [shortUrl(outcome.url)], how: r.how });
    else if (r.min) notes.push(`${r.runtime}-min:${r.min.version}`); // not visible from outside: a bound, not a verdict
  }
  return assemble({ kind: "url", value: outcome.url.slice(0, 300) }, data, results, { outcome: "ok", status: null, by: null, cause: null, tls_unverified: outcome.tlsUnverified }, notes);
}

/** JSON.stringify leaves C1 controls raw, and a terminal can act on them. Text here comes from advisories and from sites. */
export const toJson = (r: Report) => JSON.stringify(r, null, 2).replace(/[\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
