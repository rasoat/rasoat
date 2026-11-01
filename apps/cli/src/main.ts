#!/usr/bin/env bun
// rasoat: which of your versions have published vulnerabilities, and what to move to. Reads files as text, runs nothing.
import { NOTICES } from "@rasoat/core";
import { parseArgs } from "node:util";
import { serve } from "./mcp.ts";
import { langFromEnv, render, type Lang } from "./render.ts";
import { TOOL, VERSION, toJson } from "./report.ts";
import { NotATarget, anyAddress, scanTarget } from "./scan.ts";

const HELP = `${TOOL} ${VERSION} - check your versions against published vulnerabilities

Usage:
  ${TOOL} scan [dir|url]   default: the current directory
  ${TOOL} mcp              serve the read-only tools scan and fix_plan to an AI agent over stdio

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
  if (command === "mcp" && parsed.positionals.length === 1) return await serve();
  if (command !== "scan" || rest.length) return console.error(HELP), 2;
  if (o.lang && o.lang !== "vi" && o.lang !== "en") return console.error("--lang must be vi or en"), 2;

  let report;
  try {
    ({ report } = await scanTarget(target, { offline: !!o.offline, admit: anyAddress }));
  } catch (e) {
    if (e instanceof NotATarget) return console.error(e.message), 2;
    throw e;
  }
  const lang: Lang = (o.lang as Lang) ?? langFromEnv(process.env);
  console.log(o.json ? toJson(report) : render(report, lang, !!o.all));
  return report.exit_code;
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)).catch((e) => (console.error(`error: ${(e as Error).message}`), 2)));
