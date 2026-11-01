// Runtimes (Node.js, PHP, Bun): which branches still get fixes, and which vulnerabilities reach a version.
// Data: data/runtimes/<id>.json (scripts/runtimes/fetch.ts). Ranges are npm-semver strings matched with Bun.semver.
import type { Severity } from "./advisories.ts";

export type RuntimeId = "node" | "php" | "bun";

export interface RtBranch {
  cycle: string; // "22" (Node, Bun) · "8.3" (PHP)
  released: string; // YYYY-MM-DD
  eol: string | null; // YYYY-MM-DD; null = no end date announced
  latest: string;
}

export interface RtVuln {
  id: string; // CVE id, or GHSA id when there is no CVE
  severity: Severity;
  cvss: number | null;
  summary: string; // English, from the source
  published: string; // YYYY-MM-DD, or YYYY-MM when the source gives only the month
  url: string;
  vulnerable: string; // semver range
  patched: string | null; // semver range of fixed releases, when the source states it (Node.js)
}

export interface RtData {
  id: RuntimeId;
  name: string;
  fetched: string;
  sources: string[];
  branches: RtBranch[]; // newest first
  vulns: RtVuln[]; // newest first
}

/** "8.1" → "8.1.0", "v20.11.0" → "20.11.0"; null when it is not a version. */
export function normalizeRuntime(v: string): string | null {
  const m = v.trim().replace(/^v/i, "").match(/^(\d+)\.(\d+)(?:\.(\d+))?(-[0-9A-Za-z.-]+)?$/);
  return m ? `${m[1]}.${m[2]}.${m[3] ?? 0}${m[4] ?? ""}` : null;
}

export const branchOf = (id: RuntimeId, v: string) => (id === "php" ? v.split(".").slice(0, 2).join(".") : v.split(".")[0]!);

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

export interface RtCheck {
  version: string;
  branch: RtBranch | null; // null: a branch the data does not list
  eol: boolean; // the branch gets no more fixes (as of `today`)
  hits: RtVuln[]; // most severe first
  fix: string | null; // newest release of its branch if supported, else the latest of the next supported branch
  upToDate: boolean; // the newest release of a supported branch
}

export function checkRuntime(id: RuntimeId, raw: string, data: RtData, today = new Date().toISOString().slice(0, 10)): RtCheck {
  const version = normalizeRuntime(raw) ?? raw;
  const branch = data.branches.find((b) => b.cycle === branchOf(id, version)) ?? null;
  const eol = !!branch?.eol && branch.eol <= today;
  const upToDate = !!branch && !eol && Bun.semver.order(version, normalizeRuntime(branch.latest)!) >= 0;
  // The newest release of a supported branch carries every fix the project shipped for it: a source range that
  // still covers it is a data lag, not a vulnerability (same rule as WordPress; tests count the mismatches).
  const hits = upToDate
    ? []
    : data.vulns
        .filter((v) => Bun.semver.satisfies(version, v.vulnerable) && !(v.patched && Bun.semver.satisfies(version, v.patched)))
        .sort((a, b) => RANK[a.severity] - RANK[b.severity] || (b.cvss ?? 0) - (a.cvss ?? 0));
  const supported = data.branches.filter((b) => !b.eol || b.eol > today);
  const next = [...supported].reverse().find((b) => Bun.semver.order(normalizeRuntime(b.latest)!, version) > 0);
  const fix = upToDate ? null : branch && !eol ? branch.latest : (next?.latest ?? supported[0]?.latest ?? null);
  return { version, branch, eol, hits, fix, upToDate };
}
