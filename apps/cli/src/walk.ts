// Walk a directory for manifests. Reads text only, follows no symlink, skips what is not the project's own.
import { readdirSync, statSync, type Dirent } from "node:fs";
import { dirname, join, relative } from "node:path";
import { MANIFESTS, NEXT_LOCKS, declared, installedNext, wpVersionPhp, type Pin } from "./manifests.ts";

const MAX_DEPTH = 5;
const MAX_DIRS = 20_000;
const MAX_FILE = 64 * 1024 * 1024;
/** Build output, dependencies, and wp-content: plugins ship their own lockfiles, which say nothing about the site. */
const SKIP = new Set(["node_modules", "vendor", "wp-content", "dist", "build", "out", "coverage", "tmp"]);

export interface Found extends Pin {
  path: string; // relative to the scanned directory
}
export interface Walked {
  found: Found[];
  notes: ("binary-bun-lock" | "truncated")[];
}

async function read(file: string): Promise<string | null> {
  try {
    return statSync(file).size > MAX_FILE ? null : await Bun.file(file).text();
  } catch {
    return null; // unreadable or absent: says nothing
  }
}
const list = (dir: string): Dirent[] => {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
};

/** The monorepo case: scanning apps/web, whose lockfile is at the repo root. Stops at the repo's top. */
async function lockAbove(root: string): Promise<Found[]> {
  for (let dir = dirname(root), prev = root, i = 0; dir !== prev && i < 6; prev = dir, dir = dirname(dir), i++) {
    for (const name of NEXT_LOCKS) {
      const text = await read(join(dir, name));
      if (text !== null) return MANIFESTS[name]!(text).map((p) => ({ ...p, path: relative(root, join(dir, name)) }));
    }
    if (list(dir).some((e) => e.name === ".git")) return [];
  }
  return [];
}

export async function walk(root: string): Promise<Walked> {
  const found: Found[] = [];
  const notes = new Set<Walked["notes"][number]>();
  const ranges: (Found & { dir: string })[] = [];
  const lockDirs: string[] = [];
  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  for (let seen = 0; queue.length; seen++) {
    if (seen >= MAX_DIRS) {
      notes.add("truncated");
      break;
    }
    const { dir, depth } = queue.shift()!;
    const add = (pins: Pin[], file: string) => found.push(...pins.map((p) => ({ ...p, path: relative(root, file) })));
    for (const e of list(dir)) {
      const file = join(dir, e.name);
      if (e.isFile()) {
        const parse = MANIFESTS[e.name];
        if (parse) {
          const text = await read(file);
          if (text !== null) add(parse(text), file);
          if (NEXT_LOCKS.includes(e.name)) lockDirs.push(dir);
        } else if (e.name === "bun.lockb") {
          notes.add("binary-bun-lock");
        } else if (e.name === "package.json") {
          const d = declared((await read(file)) ?? "");
          add(d.pins, file);
          if (d.next) ranges.push({ product: "next", version: d.next, path: relative(root, file), dir });
        }
      } else if (e.isDirectory()) {
        if (e.name === "node_modules") {
          const nextPkg = join(file, "next/package.json");
          add(installedNext((await read(nextPkg)) ?? ""), nextPkg);
        } else if (e.name === "wp-includes") {
          const php = join(file, "version.php");
          add(wpVersionPhp((await read(php)) ?? ""), php);
        } else if (depth < MAX_DEPTH && !SKIP.has(e.name) && !e.name.startsWith(".")) {
          queue.push({ dir: file, depth: depth + 1 });
        }
      }
    }
  }
  // A range is an answer only when no lockfile above or beside it resolved it.
  const open = ranges.filter((r) => !lockDirs.some((d) => r.dir === d || r.dir.startsWith(d + "/")));
  const above = open.length ? await lockAbove(root) : [];
  found.push(...above);
  if (!above.length) found.push(...open.map(({ dir: _dir, ...r }) => r));
  return { found, notes: [...notes] };
}
