// What a reader typed into the checker: a version of something we track, or (null) a site address.
import { parseVersion } from "../advisories.ts";
import { normalizeRuntime } from "../runtimes.ts";
import { isWpVersion } from "../wordpress.ts";

export type Typed = { kind: "next" | "wordpress" | "php" | "node" | "bun"; version: string };

const PREFIX: Record<string, Typed["kind"]> = {
  next: "next", nextjs: "next", "next.js": "next",
  wordpress: "wordpress", wp: "wordpress",
  php: "php",
  node: "node", nodejs: "node", "node.js": "node",
  bun: "bun",
};

/** "14.2.3" (Next.js, as before) · "wordpress 6.4.3" · "wp 6.4" · "php 8.1.2" · "node v20.11.0" · "bun@1.1.0". */
export function parseTyped(input: string): Typed | null {
  const s = input.trim();
  const bare = parseVersion(s);
  if (bare) return { kind: "next", version: bare };
  const m = s.match(/^([a-z.]+)\s*[@:\s]\s*(v?[\d][\w.-]*)$/i);
  const kind = m && PREFIX[m[1]!.toLowerCase()];
  if (!kind) return null;
  const v = m![2]!.replace(/^v/i, "");
  if (kind === "next") return parseVersion(v) ? { kind, version: parseVersion(v)! } : null;
  if (kind === "wordpress") return isWpVersion(v) ? { kind, version: v } : null;
  const n = normalizeRuntime(v);
  return n ? { kind, version: n } : null;
}
