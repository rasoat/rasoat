// What a project's files say it runs. Files are read as text and never executed; each parser takes the text and
// returns versions, so it can be tested on the real file a package manager wrote (apps/cli/scripts/build-fixtures.ts).
import type { Product } from "@rasoat/core";

export interface Pin {
  product: Product;
  version: string; // exact, or as declared ("^14.0.0", "20", "lts/*"): verdictFor answers "not exact" for those
}

const uniq = (vs: string[]) => [...new Set(vs)];
const pins = (product: Product, vs: string[]): Pin[] => uniq(vs).map((version) => ({ product, version }));
const json = (text: string): any => {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

/** npm: v2/v3 `packages` (every nested copy), v1 `dependencies` (recursive). */
export function packageLock(text: string): Pin[] {
  const lock = json(text);
  const found: string[] = [];
  for (const [path, p] of Object.entries<any>(lock?.packages ?? {})) if (/(^|\/)node_modules\/next$/.test(path) && p?.version) found.push(p.version);
  const walk = (deps: any) => {
    for (const [name, d] of Object.entries<any>(deps ?? {})) {
      if (name === "next" && d?.version) found.push(d.version);
      walk(d?.dependencies);
    }
  };
  if (!lock?.packages) walk(lock?.dependencies);
  return pins("next", found);
}

/** pnpm: `next@14.2.3(react@18):` (v9), `/next@14.2.3:` (v6), `/next/14.2.3:` (v5). */
export const pnpmLock = (text: string): Pin[] =>
  pins("next", [...text.matchAll(/^\s*['"]?\/?next[@/](\d+\.\d+\.\d+[^:('"\s]*)/gm)].map((m) => m[1]!));

/** Yarn: a `next@…:` block header followed by `version "x"` (v1) or `version: x` (berry). */
export const yarnLock = (text: string): Pin[] =>
  pins("next", [...text.matchAll(/^"?next@[^\n]*:\r?\n\s+version:?\s+"?([^"\s]+)/gm)].map((m) => m[1]!));

/** bun.lock: `"next": ["next@15.0.0", "", …]`, any nested key. */
export const bunLock = (text: string): Pin[] =>
  pins("next", [...text.matchAll(/\["next@(\d[^"]*)"/g)].map((m) => m[1]!));

const WP_PACKAGES = new Set(["roots/wordpress", "roots/wordpress-no-content", "johnpbloch/wordpress", "johnpbloch/wordpress-core"]);
/** Composer (Bedrock and similar): the package that installs WordPress core. */
export function composerLock(text: string): Pin[] {
  const packages: any[] = json(text)?.packages ?? [];
  return pins("wordpress", packages.filter((p) => WP_PACKAGES.has(p?.name) && p?.version).map((p) => String(p.version).replace(/^v/, "")));
}

/** WordPress core's own record of its version, wp-includes/version.php. Read with a pattern, never run. */
export const wpVersionPhp = (text: string): Pin[] =>
  pins("wordpress", [...text.matchAll(/^\$wp_version\s*=\s*['"]([^'"]+)['"]/gm)].map((m) => m[1]!));

/** node_modules/next/package.json: what is installed here, which can differ from the lockfile. */
export function installedNext(text: string): Pin[] {
  const p = json(text);
  return p?.name === "next" && p?.version ? pins("next", [p.version]) : [];
}

/** package.json states a Next.js range (the caller keeps it only when no lockfile answers) and Bun's exact version. */
export function declared(text: string): { next: string | null; pins: Pin[] } {
  const p = json(text);
  const next = p?.dependencies?.next ?? p?.devDependencies?.next ?? null;
  const bun = String(p?.packageManager ?? "").match(/^bun@(\d+\.\d+\.\d+)/)?.[1];
  return { next: typeof next === "string" ? next : null, pins: bun ? pins("bun", [bun]) : [] };
}

/** One-line pin files: .nvmrc, .node-version, .php-version, .bun-version. */
export const pinFile = (product: Product) => (text: string): Pin[] => {
  const line = text.split("\n").map((l) => l.trim()).find((l) => l && !l.startsWith("#"));
  return line ? pins(product, [line.replace(/^v(?=\d)/, "")]) : [];
};

const TOOLS: Record<string, Product> = { nodejs: "node", node: "node", php: "php", bun: "bun" };
/** asdf/mise .tool-versions: `nodejs 20.11.0`. */
export const toolVersions = (text: string): Pin[] =>
  text.split("\n").flatMap((l) => {
    const [tool, version] = l.trim().split(/\s+/);
    const product = tool && TOOLS[tool];
    return product && version ? [{ product, version }] : [];
  });

/** File name → parser, for files found anywhere in the walk. */
export const MANIFESTS: Record<string, (text: string) => Pin[]> = {
  "package-lock.json": packageLock,
  "npm-shrinkwrap.json": packageLock,
  "pnpm-lock.yaml": pnpmLock,
  "yarn.lock": yarnLock,
  "bun.lock": bunLock,
  "composer.lock": composerLock,
  ".nvmrc": pinFile("node"),
  ".node-version": pinFile("node"),
  ".php-version": pinFile("php"),
  ".bun-version": pinFile("bun"),
  ".tool-versions": toolVersions,
};
/** Lockfiles that fix which Next.js a package.json range resolved to. */
export const NEXT_LOCKS = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];
