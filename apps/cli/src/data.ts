// Which snapshot a scan answers from: the newest good one of a daily download, the cached download, and the copy the
// binary was built with. The download is one plain GET; it carries nothing about what is being scanned.
import { SNAPSHOT_PATH, keepsCoverage, parseSnapshot, type Snapshot } from "@rasoat/core";
import { BUNDLED } from "@rasoat/core/bundled";
import { mkdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DAY_MS = 86_400_000;
const STALE_DAYS = 7;
const TIMEOUT_MS = 20_000;
const MAX_BYTES = 32 * 1024 * 1024;

export type Origin = "downloaded" | "cached" | "bundled";
export type DownloadProblem = "unreachable" | "invalid" | "older" | "lost-records";
export interface Loaded {
  snapshot: Snapshot;
  origin: Origin;
  ageDays: number;
  stale: boolean;
  problem: DownloadProblem | null; // why a download attempted now was not used
}

export const dataUrl = () => process.env.RASOAT_DATA_URL ?? `https://rasoat.com${SNAPSHOT_PATH}`;
const cacheFile = () => join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "rasoat", "snapshot-v1.json");

async function readCache(file: string): Promise<{ snapshot: Snapshot; ageMs: number } | null> {
  try {
    const snapshot = parseSnapshot(await Bun.file(file).json());
    return snapshot && { snapshot, ageMs: Date.now() - statSync(file).mtimeMs };
  } catch {
    return null;
  }
}

async function download(userAgent: string): Promise<{ snapshot: Snapshot; text: string } | "unreachable" | "invalid"> {
  let text: string;
  try {
    const res = await fetch(dataUrl(), { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { "user-agent": userAgent, accept: "application/json" } });
    if (!res.ok) return "unreachable";
    if (Number(res.headers.get("content-length") ?? 0) > MAX_BYTES) return "invalid";
    text = await res.text();
  } catch {
    return "unreachable";
  }
  try {
    const snapshot = parseSnapshot(JSON.parse(text));
    return snapshot ? { snapshot, text } : "invalid";
  } catch {
    return "invalid";
  }
}

function writeCache(file: string, text: string) {
  try {
    mkdirSync(join(file, ".."), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, text);
    renameSync(tmp, file); // a crash leaves the old cache, never half a file
  } catch {
    // a read-only home costs a re-download next run, nothing more
  }
}

function loaded(snapshot: Snapshot, origin: Origin, problem: DownloadProblem | null): Loaded {
  const ageDays = Math.max(0, Math.floor((Date.now() - Date.parse(snapshot.built)) / DAY_MS));
  return { snapshot, origin, ageDays, stale: ageDays > STALE_DAYS, problem };
}

export async function loadSnapshot({ offline, userAgent }: { offline: boolean; userAgent: string }): Promise<Loaded> {
  const file = cacheFile();
  const cache = await readCache(file);
  // Never go back: a cache older than the binary's own copy, or one that lost records against it, loses to the copy.
  const usable = cache && cache.snapshot.built >= BUNDLED.built && keepsCoverage(cache.snapshot, BUNDLED) ? cache : null;
  const best = usable?.snapshot ?? BUNDLED;
  const bestOrigin: Origin = usable ? "cached" : "bundled";
  if (offline || (usable && usable.ageMs < DAY_MS)) return loaded(best, bestOrigin, null);

  const got = await download(userAgent);
  if (got === "unreachable" || got === "invalid") return loaded(best, bestOrigin, got);
  if (got.snapshot.built < best.built) return loaded(best, bestOrigin, "older");
  if (!keepsCoverage(got.snapshot, best)) return loaded(best, bestOrigin, "lost-records");
  writeCache(file, got.text);
  return loaded(got.snapshot, "downloaded", null);
}
