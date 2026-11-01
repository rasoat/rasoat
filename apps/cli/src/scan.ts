// One scan of a directory or a site, whoever asked: the terminal command and the MCP tools differ only in which addresses
// they may read.
import { Refused, assertPublic, cappedGet, inspectSite, unreachableFrom, type SiteOutcome } from "@rasoat/core";
import { statSync } from "node:fs";
import { resolve } from "node:path";
import { loadSnapshot, type Loaded } from "./data.ts";
import { TOOL, VERSION, dirReport, siteReport, type Report } from "./report.ts";
import { walk } from "./walk.ts";

export const USER_AGENT = `${TOOL}-cli/${VERSION} (+https://rasoat.com/en/check)`;
const MAX_HOPS = 5;

export class NotATarget extends Error {}
type Admit = (url: URL) => Promise<void>;

/** A person at their own terminal: any address they name is theirs to read, localhost included. */
export const anyAddress: Admit = async () => {};
/** An agent chooses the address, perhaps from text it read: never reach into the user's machine or network. */
export const publicAddress: Admit = assertPublic;

const isDir = (p: string) => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};

/** A directory if one has that name; a URL if it says so or looks like a host. */
function classify(arg: string): { kind: "dir"; path: string } | { kind: "url"; url: string } | null {
  if (/^https?:\/\//i.test(arg)) return { kind: "url", url: arg };
  if (isDir(arg)) return { kind: "dir", path: resolve(arg) };
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/\S*)?$/i.test(arg)) return { kind: "url", url: `https://${arg}` };
  return null;
}

/** Throws NotATarget, and Refused when `admit` refuses an address. Every other site failure is a report, not a throw. */
export async function scanTarget(target: string, opts: { offline: boolean; admit: Admit }): Promise<{ report: Report; data: Loaded }> {
  const where = classify(target);
  if (!where) throw new NotATarget(`Not a directory or a site address: ${target}`);
  const data = await loadSnapshot({ offline: opts.offline, userAgent: USER_AGENT });
  if (where.kind === "dir") return { report: dirReport(where.path, await walk(where.path), data), data };
  const get = cappedGet({
    userAgent: USER_AGENT,
    admit: async (href, hop) => {
      if (hop > MAX_HOPS) throw new Error("too many redirects");
      const url = new URL(href);
      if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("not http(s)");
      await opts.admit(url);
      return url;
    },
  });
  const outcome: SiteOutcome = await inspectSite(where.url, get, { requirements: data.snapshot.requirements, runtimes: data.snapshot.runtimes }).catch((e) => {
    if (e instanceof Refused) throw e;
    return unreachableFrom(e);
  });
  return { report: siteReport(where.url, outcome, data), data };
}
