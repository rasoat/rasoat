#!/usr/bin/env bun
// Release binaries: compile per platform, smoke-test the native one, refuse a binary that carries this machine's build
// path, write SHA256SUMS. Usage: bun apps/cli/scripts/build.ts [--native]  → dist/cli/
import { $ } from "bun";
import { mkdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("../../../", import.meta.url).pathname;
const OUT = join(ROOT, "dist/cli");
const NATIVE = `bun-${process.platform}-${process.arch}`;
const TARGETS = process.argv.includes("--native") ? [NATIVE] : ["bun-linux-x64", "bun-linux-arm64", "bun-darwin-arm64", "bun-darwin-x64", "bun-windows-x64"];

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const sums: string[] = [];
for (const target of TARGETS) {
  const name = `rasoat-${target.replace(/^bun-/, "")}${target.includes("windows") ? ".exe" : ""}`;
  const file = join(OUT, name);
  await $`bun build --compile --minify --target=${target} apps/cli/src/main.ts --outfile ${file}`.cwd(ROOT).quiet();
  const bytes = await Bun.file(file).bytes();
  if (Buffer.from(bytes).toString("latin1").includes(ROOT)) throw new Error(`${name} contains the build path ${ROOT}: not releasable`);
  sums.push(`${new Bun.CryptoHasher("sha256").update(bytes).digest("hex")}  ${name}`);
  console.log(name, `${Math.round(statSync(file).size / 1e6)} MB`);
}
await Bun.write(join(OUT, "SHA256SUMS"), sums.join("\n") + "\n");

const native = join(OUT, `rasoat-${NATIVE.replace(/^bun-/, "")}`);
const smoke = await $`${native} scan apps/cli/fixtures/npm --offline --json`.cwd(ROOT).nothrow().quiet();
const report = JSON.parse(smoke.stdout.toString());
if (smoke.exitCode !== 1 || report.results[0].version !== "14.2.3" || report.results[0].status !== "vulnerable") throw new Error("smoke test failed");
console.log(`smoke: ${NATIVE} scan fixtures/npm → exit 1, next 14.2.3 vulnerable, fix ${report.results[0].fix}`);
console.log(`wrote ${OUT}/SHA256SUMS`);
