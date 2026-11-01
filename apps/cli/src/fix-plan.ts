// From a report to what to change. The plan is knowledge only: which version, what it asks of the runtime, the command a
// person or their agent would run. Nothing here runs anything.
import type { Product, Status, VerdictAdvisory } from "@rasoat/core";
import { basename, dirname } from "node:path";
import type { Loaded } from "./data.ts";
import type { Report, Result } from "./report.ts";

const TOP_ADVISORIES = 5;
const NPM_ADD: Record<string, string> = { "package-lock.json": "npm install", "npm-shrinkwrap.json": "npm install", "pnpm-lock.yaml": "pnpm add", "yarn.lock": "yarn add", "bun.lock": "bun add", "package.json": "npm install" };
/** A command carries a version from a downloaded file into something an agent may run: only a plain version gets there. */
const PLAIN_VERSION = /^\d+\.\d+(\.\d+)?(-[0-9A-Za-z.-]+)?$/;

export type Action = "upgrade" | "no-published-fix" | "cannot-judge";

/** One place to make the change. `command` is null where there is no one right command; `how` always says what to do. */
export interface Change {
  file: string; // the file the version was read from, relative to the scanned directory; or a URL
  cwd: string | null;
  command: string | null;
  how: string;
}

export interface Requirement {
  runtime: "node" | "php";
  needs: string;
  found: string | null; // the version this scan saw, if any
  met: boolean | null; // null: this scan saw no exact version
}

export interface Step {
  product: Product;
  version: string | null;
  status: Status;
  action: Action;
  move_to: string | null;
  crosses_major: boolean;
  requires: Requirement | null; // settle this first: the target version does not run on less
  changes: Change[];
  guides: string[];
  advisories: { total: number; worst: Pick<VerdictAdvisory, "id" | "severity" | "url">[] };
}

export interface FixPlan {
  schema: 1;
  target: Report["target"];
  data: Report["data"];
  site: Report["site"];
  applied: false; // always: this tool changes nothing
  steps: Step[];
  clean: { product: Product; version: string | null }[];
  rescan: { tool: "scan"; arguments: { target: string } }; // not a shell line: a directory's name is the project's text
  not_checked: string[];
  notices: string[];
}

/** The part of a version that makes a move risky: 14 for Next.js and Node.js, 6.4 for WordPress and PHP. */
const line = (product: Product, v: string) => v.split(".").slice(0, product === "wordpress" || product === "php" ? 2 : 1).join(".");

/** The official guide for each major a Next.js move passes through; WordPress has one. Nothing is claimed for the rest. */
export function guides(product: Product, from: string | null, to: string): string[] {
  if (product === "wordpress") return ["https://wordpress.org/documentation/article/updating-wordpress/"];
  if (product !== "next" || !from) return [];
  const out: string[] = [];
  for (let m = Number(from.split(".")[0]) + 1; m <= Number(to.split(".")[0]); m++) if (m >= 14) out.push(`https://nextjs.org/docs/app/guides/upgrading/version-${m}`);
  return out;
}

function change(product: Product, file: string, to: string, isSite: boolean): Change {
  if (isSite) return { file, cwd: null, command: null, how: `This address was read from outside. In the project or on the server behind it, move ${product} to ${to}.` };
  const name = basename(file);
  const plain = PLAIN_VERSION.test(to);
  // A lockfile above the scanned directory: the package that declares the dependency is here, not there. The installed
  // copy in node_modules: the project is above it.
  const project = file.replace(/(^|\/)node_modules\/.*$/, "$1package.json");
  const cwd = project.startsWith("..") ? "." : dirname(project);
  if (product === "next") {
    const add = NPM_ADD[name] ?? "npm install";
    const manager = add.split(" ")[0];
    return { file, cwd, command: plain ? `${add} next@${to}` : null, how: `Move next to ${to} with ${manager}, in the package that declares it, then commit the lockfile.` };
  }
  if (product === "wordpress") {
    if (name === "composer.lock") return { file, cwd, command: null, how: `Raise the WordPress package in composer.json to ${to}, then run composer update for it.` };
    const root = dirname(dirname(file));
    return { file, cwd: root, command: plain ? `wp core update --version=${to}` : null, how: `Back up the database and files first, then update core to ${to} (the command needs WP-CLI).` };
  }
  return { file, cwd, command: null, how: `Set ${product} to ${to} in ${name}, and install that version wherever the project runs.` };
}

function requirement(r: Result, to: string, results: Result[], loaded: Loaded): Requirement | null {
  const req = loaded.snapshot.requirements;
  const [runtime, needs] = r.product === "next"
    ? ["node" as const, req.next.find((n) => n.v === to)?.node]
    : r.product === "wordpress"
      ? ["php" as const, req.wordpress[to.split(".").slice(0, 2).join(".")]]
      : [null, undefined];
  if (!runtime || !needs) return null;
  const seen = results.find((x) => x.product === runtime);
  const exact = seen?.version && /^\d+\.\d+\.\d+/.test(seen.version) ? seen.version : null;
  const range = r.product === "wordpress" ? `>=${needs}` : needs;
  return { runtime, needs: range, found: seen?.version ?? null, met: exact ? Bun.semver.satisfies(exact, range) : null };
}

function step(r: Result, report: Report, loaded: Loaded): Step {
  const to = r.fix;
  const isSite = report.target.kind === "url";
  const action: Action = r.status === "unknown" && !to ? "cannot-judge" : to ? "upgrade" : "no-published-fix";
  return {
    product: r.product,
    version: r.version,
    status: r.status,
    action,
    move_to: to,
    crosses_major: !!(to && r.version && line(r.product, to) !== line(r.product, r.version)),
    requires: to ? requirement(r, to, report.results, loaded) : null,
    changes: to ? r.sources.map((file) => change(r.product, file, to, isSite)) : r.sources.map((file) => ({ file, cwd: null, command: null, how: whyNoMove(r) })),
    guides: to ? guides(r.product, r.version, to) : [],
    advisories: { total: r.advisories.length, worst: r.advisories.slice(0, TOP_ADVISORIES).map(({ id, severity, url }) => ({ id, severity, url })) },
  };
}

function whyNoMove(r: Result): string {
  if (r.status !== "unknown") return "No published release clears every advisory. Read the advisories for a workaround, and watch for a release.";
  if (r.reason === "version-not-exact") return "The version is a range or a partial number. Commit a lockfile or an exact version, then scan again.";
  if (r.reason === "version-hidden") return "The site does not show its version. Scan the project directory instead.";
  return "This version is not in the data, so no verdict is possible. Check it against the project's own release notes.";
}

export function fixPlan(report: Report, loaded: Loaded): FixPlan {
  const clean = report.results.filter((r) => r.status === "ok");
  return {
    schema: 1,
    target: report.target,
    data: report.data,
    site: report.site,
    applied: false,
    steps: report.results.filter((r) => r.status !== "ok").map((r) => step(r, report, loaded)),
    clean: clean.map((r) => ({ product: r.product, version: r.version })),
    rescan: { tool: "scan", arguments: { target: report.target.value } },
    not_checked: report.not_checked,
    notices: report.notices,
  };
}
