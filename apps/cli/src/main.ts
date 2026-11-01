#!/usr/bin/env bun
// rasoat: which of your versions have published vulnerabilities, and what to move to. Reads files as text, runs nothing.
import { cappedGet, inspectSite, unreachableFrom, NOTICES, type SiteOutcome } from "@rasoat/core";
import { statSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadSnapshot } from "./data.ts";
import { langFromEnv, render, type Lang } from "./render.ts";
import { TOOL, VERSION, dirReport, siteReport, toJson } from "./report.ts";
import { walk } from "./walk.ts";

const HELP = `${TOOL} ${VERSION} - check your versions against published vulnerabilities

Usage:
  ${TOOL} scan [dir|url]   default: the current directory

Options:
  --json        print the report as JSON (schema 1)
  --offline     do not download advisory data; use what is already here
  --all         list every advisory, not the worst 5
  --lang vi|en  default: from LANG
  -h, --help    -v, --version

Reads:   lockfiles, wp-includes/version.php, composer.lock, version pin files. As text; it never runs project code.
Sends:   one GET for the advisory data, at most once a day, with no project information in it.
         A URL scan fetches that site's public page and scripts, as a browser does.
Writes:  only its data cache, ~/.cache/rasoat/.
Exit:    0 all clean, 1 vulnerable or unsupported, 2 usage or error, 3 nothing or not everything could be judged.

${NOTICES.join("\n")}
`;

const USER_AGENT = `${TOOL}-cli/${VERSION} (+https://rasoat.com/en/check)`;
const MAX_HOPS = 5;

/** On the user's own machine any address they name is theirs to read, localhost included: http(s) only, no loops. */
const get = cappedGet({
  userAgent: USER_AGENT,
  admit: async (href, hop) => {
    if (hop > MAX_HOPS) throw new Error("too many redirects");
    const url = new URL(href);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("not http(s)");
    return url;
  },
});

const isDir = (p: string) => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};

/** A directory if one has that name; a URL if it says so or looks like a host. */
export function classify(arg: string): { kind: "dir"; path: string } | { kind: "url"; url: string } | null {
  if (/^https?:\/\//i.test(arg)) return { kind: "url", url: arg };
  if (isDir(arg)) return { kind: "dir", path: resolve(arg) };
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/\S*)?$/i.test(arg)) return { kind: "url", url: `https://${arg}` };
  return null;
}

async function main(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: { json: { type: "boolean" }, offline: { type: "boolean" }, all: { type: "boolean" }, lang: { type: "string" }, help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" } },
    });
  } catch (e) {
    console.error((e as Error).message);
    return 2;
  }
  const { values: o, positionals: [command, target = ".", ...rest] } = parsed;
  if (o.version) return console.log(VERSION), 0;
  if (o.help || !command) return console.log(HELP), command || o.help ? 0 : 2;
  if (command !== "scan" || rest.length) return console.error(HELP), 2;
  if (o.lang && o.lang !== "vi" && o.lang !== "en") return console.error("--lang must be vi or en"), 2;

  const where = classify(target);
  if (!where) return console.error(`Not a directory or a site address: ${target}`), 2;
  const data = await loadSnapshot({ offline: !!o.offline, userAgent: USER_AGENT });
  let report;
  if (where.kind === "dir") {
    report = dirReport(where.path, await walk(where.path), data);
  } else {
    const outcome: SiteOutcome = await inspectSite(where.url, get, { requirements: data.snapshot.requirements, runtimes: data.snapshot.runtimes }).catch(unreachableFrom);
    report = siteReport(where.url, outcome, data);
  }
  const lang: Lang = (o.lang as Lang) ?? langFromEnv(process.env);
  console.log(o.json ? toJson(report) : render(report, lang, !!o.all));
  return report.exit_code;
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)).catch((e) => (console.error(`error: ${(e as Error).message}`), 2)));
