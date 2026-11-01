#!/usr/bin/env bun
// Real manifests for the CLI's tests, each written by the tool that owns the format; nothing hand-typed, nothing installed
// (--lockfile-only, --no-install). Usage: bun apps/cli/scripts/build-fixtures.ts  → apps/cli/fixtures/
import { $ } from "bun";
import { mkdirSync, readdirSync, rmSync } from "node:fs";

const OUT = new URL("../fixtures/", import.meta.url).pathname;
const pkg = (next: string) => JSON.stringify({ name: "fixture", private: true, dependencies: { next, react: "18.3.1", "react-dom": "18.3.1" } }, null, 2);

async function project(name: string, next: string, run: (cwd: string) => Promise<unknown>, keep: string[]) {
  const cwd = OUT + name;
  mkdirSync(cwd, { recursive: true });
  await Bun.write(`${cwd}/package.json`, pkg(next));
  await run(cwd);
  for (const f of readdirSync(cwd)) if (![...keep, "package.json"].includes(f)) rmSync(`${cwd}/${f}`, { recursive: true });
  console.log(name, keep.join(" "));
}

rmSync(OUT, { recursive: true, force: true });
await project("npm", "14.2.3", (c) => $`npm install --package-lock-only --ignore-scripts --no-audit --no-fund`.cwd(c).quiet(), ["package-lock.json"]);
await project("pnpm", "^13.5.0", (c) => $`pnpm install --lockfile-only --ignore-scripts`.cwd(c).quiet(), ["pnpm-lock.yaml"]);
await project("bun", "15.0.0", (c) => $`bun install --lockfile-only --ignore-scripts`.cwd(c).quiet(), ["bun.lock"]);
await project("yarn-v1", "^12.3.0", (c) => $`npx --yes yarn@1.22.22 install --ignore-scripts --non-interactive`.cwd(c).quiet(), ["yarn.lock"]);
await project("yarn-berry", "16.0.0", async (c) => {
  await Bun.write(`${c}/.yarnrc.yml`, "nodeLinker: node-modules\n");
  await Bun.write(`${c}/yarn.lock`, "");
  await $`npx --yes @yarnpkg/cli-dist@4.5.0 install --mode=update-lockfile`.cwd(c).quiet();
}, ["yarn.lock"]);

// WordPress core's own file at a tag, and a Bedrock-style composer.lock.
const wpDir = OUT + "wordpress/wp-includes";
mkdirSync(wpDir, { recursive: true });
const res = await fetch("https://raw.githubusercontent.com/WordPress/WordPress/6.4.3/wp-includes/version.php");
if (!res.ok) throw new Error(`version.php ${res.status}`);
await Bun.write(`${wpDir}/version.php`, await res.text());

const bedrock = OUT + "bedrock";
mkdirSync(bedrock, { recursive: true });
await Bun.write(`${bedrock}/composer.json`, JSON.stringify({ name: "fixture/bedrock", require: { "roots/wordpress-no-content": "6.5.2" }, config: { "allow-plugins": false } }, null, 2));
await $`composer update --no-install --no-scripts --no-plugins --no-interaction`.cwd(bedrock).quiet();
const lock = await Bun.file(`${bedrock}/composer.lock`).json();
console.log("bedrock", lock.packages.map((p: any) => `${p.name}@${p.version}`).join(" "));

// Runtime pins, as the version managers write them.
const pins = OUT + "pins";
mkdirSync(pins, { recursive: true });
await Bun.write(`${pins}/.nvmrc`, "v18.12.0\n");
await Bun.write(`${pins}/.php-version`, "8.1\n");
await Bun.write(`${pins}/.tool-versions`, "bun 1.1.0\nruby 3.3.0\n");
