// What the CLI's end-to-end tests share: the real program in a subprocess, with its own cache, and no download.
// A function, not module state: bun runs all test files in one process, and a module's hooks bind to the first file only.
import { afterAll, beforeEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const FIXTURES = new URL("../fixtures/", import.meta.url).pathname;
const MAIN = new URL("./main.ts", import.meta.url).pathname;
/** An address nothing listens on: runs that must not depend on a download. */
export const NOWHERE = "http://127.0.0.1:9/none";

export function cliKit() {
  const tmp = mkdtempSync(join(tmpdir(), "rasoat-test-"));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));
  let cache = "";
  let n = 0;
  const dir = () => {
    const d = join(tmp, `d${n++}`);
    mkdirSync(d, { recursive: true });
    return d;
  };
  beforeEach(() => {
    cache = dir();
  });
  async function rasoat(args: string[], env: Record<string, string> = {}) {
    const p = Bun.spawn(["bun", MAIN, ...args], { stdout: "pipe", stderr: "pipe", env: { ...process.env, XDG_CACHE_HOME: cache, RASOAT_DATA_URL: NOWHERE, LC_ALL: "", LC_MESSAGES: "", LANG: "en_US.UTF-8", ...env } });
    const [out, err] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text()]);
    return { code: await p.exited, out, err };
  }
  const scanJson = async (target: string, env?: Record<string, string>, extra: string[] = ["--offline"]) => {
    const r = await rasoat(["scan", target, "--json", ...extra], env);
    return { ...r, report: JSON.parse(r.out) };
  };
  return { dir, rasoat, scanJson, cache: () => cache };
}
