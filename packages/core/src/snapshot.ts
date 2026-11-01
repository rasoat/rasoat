// The advisory snapshot: every dataset a verdict needs, as one document. The site serves it at SNAPSHOT_PATH; the CLI
// carries a copy from its build and downloads newer ones. A download is untrusted input: parseSnapshot checks its shape.
import type { Advisory } from "./advisories.ts";
import type { FrameworkRuntimes } from "./checker/runtime.ts";
import type { RtData, RuntimeId } from "./runtimes.ts";
import type { WpData } from "./wordpress.ts";

export const SNAPSHOT_PATH = "/data/snapshot-v1.json";

// Vercel's brand rules require this sentence, verbatim, on any site using its marks.
export const VERCEL_ATTRIBUTION =
  "Vercel, the Vercel design, Next.js and related marks, designs and logos are trademarks or registered trademarks of Vercel, Inc. or its affiliates in the US and other countries.";
// NVD's terms ask API users to show this sentence, verbatim.
export const NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD.";
/** What anything built on the data must show. */
export const NOTICES = [
  "Independent project, not affiliated with Vercel, WordPress, the OpenJS Foundation, The PHP Group or Oven.",
  VERCEL_ATTRIBUTION,
  NVD_NOTICE,
  "Next.js advisories: GitHub Advisory Database, CC-BY-4.0. WordPress release status: WordPress.org. Node.js: nodejs/security-wg. Release lines: endoflife.date.",
];

export interface NextData {
  source: string;
  license: string;
  fetched: string;
  advisories: Advisory[];
}

export interface Snapshot {
  format: 1;
  built: string; // YYYY-MM-DD: the newest `fetched` of its datasets
  notices: string[];
  next: NextData;
  wordpress: WpData;
  runtimes: Record<RuntimeId, RtData>;
  requirements: FrameworkRuntimes;
}

export function makeSnapshot(parts: Pick<Snapshot, "next" | "wordpress" | "runtimes" | "requirements">): Snapshot {
  const dates = [parts.next.fetched, parts.wordpress.fetched, ...Object.values(parts.runtimes).map((r) => r.fetched)];
  return { format: 1, built: dates.sort().at(-1)!, notices: NOTICES, ...parts };
}

const isObject = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const isDate = (v: unknown) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
const isText = (v: unknown) => typeof v === "string";
const isLink = (v: unknown) => typeof v === "string" && /^https?:\/\//.test(v); // one real source is http: openssl.org, 2015

const isAdvisory = (a: any) =>
  isObject(a) && isText(a.ghsa) && isText(a.severity) && isText(a.summary) && isLink(a.url) &&
  Array.isArray(a.ranges) && a.ranges.every((r: any) => isObject(r) && isText(r.vulnerable) && (r.patched === null || isText(r.patched)));
const isCve = (c: any) =>
  isObject(c) && isText(c.cve) && isText(c.severity) && isText(c.summary) && isLink(c.url) &&
  Array.isArray(c.ranges) && c.ranges.every((r: any) => isObject(r) && isText(r.end) && (r.start === null || isText(r.start)));
const isRuntime = (r: any) =>
  isObject(r) && isText(r.id) && isDate(r.fetched) &&
  Array.isArray(r.branches) && r.branches.every((b: any) => isObject(b) && isText(b.cycle) && isText(b.latest) && (b.eol === null || isText(b.eol))) &&
  Array.isArray(r.vulns) && r.vulns.every((v: any) => isObject(v) && isText(v.id) && isText(v.severity) && isText(v.summary) && isLink(v.url) && isText(v.vulnerable));

/** The snapshot, or null when it is not one this version can read. A verdict from malformed data would be worse than none. */
export function parseSnapshot(raw: unknown): Snapshot | null {
  if (!isObject(raw) || raw.format !== 1 || !isDate(raw.built) || !Array.isArray(raw.notices)) return null;
  const { next, wordpress, runtimes, requirements } = raw;
  if (!isObject(next) || !Array.isArray(next.advisories) || !next.advisories.every(isAdvisory)) return null;
  if (!isObject(wordpress) || !isObject(wordpress.stable) || !Array.isArray(wordpress.cves) || !wordpress.cves.every(isCve)) return null;
  if (!isObject(runtimes) || ![runtimes.node, runtimes.php, runtimes.bun].every(isRuntime)) return null;
  if (!isObject(requirements) || !Array.isArray(requirements.next) || !isObject(requirements.wordpress)) return null;
  return raw as unknown as Snapshot;
}

/** False when a newer-looking snapshot has lost so many records that it would call vulnerable versions clean. */
export function keepsCoverage(candidate: Snapshot, floor: Snapshot, tolerance = 0.9): boolean {
  const count = (s: Snapshot) => [s.next.advisories.length, s.wordpress.cves.length, ...Object.values(s.runtimes).map((r) => r.vulns.length)];
  const have = count(candidate);
  return count(floor).every((n, i) => have[i]! >= n * tolerance);
}
