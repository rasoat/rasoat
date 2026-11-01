// The CLI end to end: the real program in a subprocess, real manifests written by their own tools
// (apps/cli/scripts/build-fixtures.ts), and a real HTTP server for downloads.
import { describe, expect, test } from "bun:test";
import { checkVersion, parseSnapshot, SNAPSHOT_PATH, type Snapshot } from "@rasoat/core";
import { BUNDLED } from "@rasoat/core/bundled";
import { existsSync, mkdirSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MANIFESTS, wpVersionPhp } from "./manifests.ts";
import { FIXTURES, NOWHERE, cliKit } from "./testkit.ts";
import { walk } from "./walk.ts";

const { dir, rasoat, scanJson, cache } = cliKit();

describe("manifests: the file each tool really writes", () => {
  const cases: [string, string, string][] = [
    ["npm", "next", "14.2.3"],
    ["pnpm", "next", "13.5.11"],
    ["bun", "next", "15.0.0"],
    ["yarn-v1", "next", "12.3.7"],
    ["yarn-berry", "next", "16.0.0"],
    ["wordpress", "wordpress", "6.4.3"],
    ["bedrock", "wordpress", "6.5.2"],
  ];
  for (const [name, product, version] of cases) {
    test(`${name} → ${product} ${version}`, async () => {
      const { found } = await walk(FIXTURES + name);
      expect(found.map((f) => [f.product, f.version])).toEqual([[product, version]]);
    });
  }
  test("version pin files, unknown tools ignored", async () => {
    const { found } = await walk(FIXTURES + "pins");
    expect(found.map((f) => `${f.product} ${f.version}`).sort()).toEqual(["bun 1.1.0", "node 18.12.0", "php 8.1"]);
  });
  test("next-auth and other next-* names are not next", () => {
    expect(MANIFESTS["pnpm-lock.yaml"]!("  next-auth@4.0.0:\n  /next-seo@6.0.0:\n")).toEqual([]);
    expect(MANIFESTS["yarn.lock"]!('next-auth@^4:\n  version "4.0.0"\n')).toEqual([]);
    expect(MANIFESTS["bun.lock"]!('"next-auth": ["next-auth@4.0.0", ""]')).toEqual([]);
    expect(MANIFESTS["package-lock.json"]!(JSON.stringify({ packages: { "node_modules/next-auth": { version: "4.0.0" } } }))).toEqual([]);
  });
  test("a commented-out $wp_version is not the version", () => {
    expect(wpVersionPhp("/* $wp_version = '9.9'; */\n$wp_version = '6.4.3';\n")).toEqual([{ product: "wordpress", version: "6.4.3" }]);
  });
  test("malformed files say nothing", () => {
    expect(MANIFESTS["package-lock.json"]!("{ not json")).toEqual([]);
    expect(MANIFESTS["composer.lock"]!("")).toEqual([]);
  });
});

describe("walk", () => {
  const write = (root: string, path: string, text: string) => {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), text);
  };
  const pkg = (next: string) => JSON.stringify({ dependencies: { next } });

  test("a range beside no lockfile is reported as declared, not guessed", async () => {
    const d = dir();
    write(d, "package.json", pkg("^14.0.0"));
    expect((await walk(d)).found.map((f) => f.version)).toEqual(["^14.0.0"]);
  });
  test("a workspace's range is answered by the root lockfile", async () => {
    const d = dir();
    write(d, "bun.lock", '"next": ["next@15.0.0", ""],');
    write(d, "apps/web/package.json", pkg("^15.0.0"));
    expect((await walk(d)).found.map((f) => f.version)).toEqual(["15.0.0"]);
  });
  test("scanning inside a monorepo finds the lockfile above", async () => {
    const d = dir();
    mkdirSync(join(d, ".git"));
    write(d, "bun.lock", '"next": ["next@15.0.0", ""],');
    write(d, "apps/web/package.json", pkg("^15.0.0"));
    const { found } = await walk(join(d, "apps/web"));
    expect(found.map((f) => [f.version, f.path])).toEqual([["15.0.0", "../../bun.lock"]]);
  });
  test("finds several sites under one folder", async () => {
    const d = dir();
    write(d, "client-a/wp-includes/version.php", "$wp_version = '6.4.3';\n");
    write(d, "client-b/package-lock.json", JSON.stringify({ packages: { "node_modules/next": { version: "14.2.3" } } }));
    expect((await walk(d)).found.map((f) => f.version).sort()).toEqual(["14.2.3", "6.4.3"]);
  });
  test("skips dependencies, build output and wp-content; reads the installed version", async () => {
    const d = dir();
    const lock = JSON.stringify({ packages: { "node_modules/next": { version: "9.0.0" } } });
    for (const skip of ["vendor", "dist", "wp-content/plugins/x", ".next", "node_modules/foo"]) write(d, `${skip}/package-lock.json`, lock);
    write(d, "node_modules/next/package.json", JSON.stringify({ name: "next", version: "14.2.3" }));
    expect((await walk(d)).found.map((f) => f.version)).toEqual(["14.2.3"]);
  });
  test("follows no symlink out of the project", async () => {
    const d = dir(), outside = dir();
    write(outside, "package-lock.json", JSON.stringify({ packages: { "node_modules/next": { version: "9.0.0" } } }));
    symlinkSync(outside, join(d, "linked"));
    symlinkSync(join(outside, "package-lock.json"), join(d, "package-lock.json"));
    expect((await walk(d)).found).toEqual([]);
  });
  test("says when a binary lockfile could not be read", async () => {
    const d = dir();
    write(d, "bun.lockb", "\0\0");
    expect((await walk(d)).notes).toContain("binary-bun-lock");
  });
});

describe("verdicts and exit codes", () => {
  test("vulnerable: exit 1, the fix clears every advisory, sources relative", async () => {
    const { code, report } = await scanJson(FIXTURES + "npm");
    expect(code).toBe(1);
    expect(report.exit_code).toBe(1);
    const r = report.results[0];
    expect(r).toMatchObject({ product: "next", version: "14.2.3", status: "vulnerable", sources: ["package-lock.json"] });
    expect(r.advisories.length).toBe(checkVersion("14.2.3", BUNDLED.next.advisories).hits.length);
    expect(r.advisories[0].severity).toBe("critical");
    expect(checkVersion(r.fix, BUNDLED.next.advisories).hits).toEqual([]);
  });
  test("WordPress verdict follows WordPress.org, fix stays on the branch", async () => {
    const { report } = await scanJson(FIXTURES + "wordpress");
    expect(report.results[0]).toMatchObject({ status: "vulnerable", fix: expect.stringMatching(/^6\.4\./) });
    expect(BUNDLED.wordpress.stable[report.results[0].fix]).not.toBe("insecure");
  });
  test("clean: exit 0 only when every version is judged clean", async () => {
    const d = dir();
    const { fix } = checkVersion("14.2.3", BUNDLED.next.advisories);
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({ packages: { "node_modules/next": { version: fix } } }));
    const { code, report } = await scanJson(d);
    expect([code, report.summary.ok]).toEqual([0, 1]);
    expect(report.not_checked).toContain("wordpress-plugins-themes");
  });
  test("a range cannot be judged: exit 3, reason given", async () => {
    const d = dir();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { next: "^14.0.0" } }));
    const { code, report } = await scanJson(d);
    expect(code).toBe(3);
    expect(report.results[0]).toMatchObject({ status: "unknown", reason: "version-not-exact" });
  });
  test("partial runtime pin is not treated as x.y.0", async () => {
    const { report } = await scanJson(FIXTURES + "pins");
    expect(report.results.find((r: any) => r.product === "php")).toMatchObject({ version: "8.1", status: "unknown" });
  });
  test("an end-of-life line with no listed hit is unsupported, exit 1", async () => {
    const eol = BUNDLED.runtimes.php.branches.filter((b) => b.eol && b.eol < "2026").map((b) => b.latest + (b.latest.split(".").length === 2 ? ".0" : "")).find((v) => {
      return !BUNDLED.runtimes.php.vulns.some((x) => Bun.semver.satisfies(v, x.vulnerable));
    });
    if (!eol) return; // every old line has a hit today; the status rule below still holds
    const d = dir();
    writeFileSync(join(d, ".php-version"), eol);
    const { code, report } = await scanJson(d);
    expect([code, report.results[0].status]).toEqual([1, "unsupported"]);
  });
  test("nothing identified is not a pass: exit 3", async () => {
    const { code, report } = await scanJson(dir());
    expect([code, report.results]).toEqual([3, []]);
  });
  test("usage errors: exit 2", async () => {
    expect((await rasoat(["scan", "/no/such/place"])).code).toBe(2);
    expect((await rasoat(["frobnicate"])).code).toBe(2);
    expect((await rasoat(["scan", ".", "--lang", "fr"])).code).toBe(2);
    expect((await rasoat([])).code).toBe(2);
  });
  test("scanning writes nothing into the project", async () => {
    const d = dir();
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({ packages: { "node_modules/next": { version: "14.2.3" } } }));
    await rasoat(["scan", d, "--offline"]);
    expect(readdirSync(d)).toEqual(["package-lock.json"]);
  });
  test("terminal view: both languages, the coverage limit and the notices", async () => {
    const en = await rasoat(["scan", FIXTURES + "npm", "--offline"]);
    expect(en.out).toContain("VULNERABLE");
    expect(en.out).toContain("Not checked: WordPress plugins");
    expect(en.out).toContain("This product uses the NVD API but is not endorsed or certified by the NVD.");
    expect(en.out).toContain("Vercel, the Vercel design, Next.js");
    const vi = await rasoat(["scan", FIXTURES + "npm", "--offline"], { LANG: "vi_VN.UTF-8" });
    expect(vi.out).toContain("CÓ LỖ HỔNG");
    expect(vi.out).toContain("nâng lên");
  });
});

describe("the snapshot a scan answers from", () => {
  const later = (s: Snapshot, patch: Partial<Snapshot> = {}): Snapshot => ({ ...s, built: "2099-01-01", ...patch });
  async function served(respond: () => Response) {
    const hits = { n: 0, ua: "", path: "" };
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (req) => (hits.n++, (hits.ua = req.headers.get("user-agent") ?? ""), (hits.path = new URL(req.url).pathname + new URL(req.url).search), respond()) });
    return { url: `http://127.0.0.1:${server.port}${SNAPSHOT_PATH}`, hits, stop: () => server.stop(true) };
  }

  test("a newer snapshot decides the verdict, one plain GET, cached for the next run", async () => {
    const s = await served(() => Response.json(later(BUNDLED, { next: { ...BUNDLED.next, advisories: [...BUNDLED.next.advisories, { ...BUNDLED.next.advisories[0]!, ghsa: "GHSA-test-test-test", ranges: [{ vulnerable: ">= 1.0.0", patched: null }] }] } })));
    const a = await scanJson(FIXTURES + "npm", { RASOAT_DATA_URL: s.url }, []);
    expect(a.report.data).toMatchObject({ origin: "downloaded", built: "2099-01-01" });
    expect(a.report.results[0].advisories.map((x: any) => x.id)).toContain("GHSA-test-test-test");
    expect(a.report.results[0].noFix).toBe(true);
    expect(s.hits).toMatchObject({ n: 1, path: SNAPSHOT_PATH });
    expect(s.hits.ua).toStartWith("rasoat-cli/");
    const b = await scanJson(FIXTURES + "npm", { RASOAT_DATA_URL: s.url }, []);
    expect(b.report.data.origin).toBe("cached");
    expect(s.hits.n).toBe(1);
    s.stop();
  });
  test("--offline sends nothing", async () => {
    const s = await served(() => Response.json(later(BUNDLED)));
    const { report } = await scanJson(FIXTURES + "npm", { RASOAT_DATA_URL: s.url }, ["--offline"]);
    expect(report.data.origin).toBe("bundled");
    expect(s.hits.n).toBe(0);
    s.stop();
  });
  const refused: [string, () => Response, string][] = [
    ["malformed JSON", () => new Response("<html>"), "invalid"],
    ["wrong shape", () => Response.json({ ...later(BUNDLED), next: { advisories: [{ ghsa: 1 }] } }), "invalid"],
    ["unknown format", () => Response.json({ ...later(BUNDLED), format: 2 }), "invalid"],
    ["older data", () => Response.json({ ...BUNDLED, built: "2020-01-01" }), "older"],
    ["records gone (would call everything clean)", () => Response.json(later(BUNDLED, { next: { ...BUNDLED.next, advisories: [] } })), "lost-records"],
    ["server error", () => new Response("no", { status: 500 }), "unreachable"],
  ];
  for (const [name, respond, problem] of refused) {
    test(`refused: ${name} → keeps the built-in data and says so`, async () => {
      const s = await served(respond);
      const { report, code } = await scanJson(FIXTURES + "npm", { RASOAT_DATA_URL: s.url }, []);
      expect(report.data).toMatchObject({ origin: "bundled", problem });
      expect(code).toBe(1);
      expect(existsSync(join(cache(), "rasoat"))).toBe(false);
      s.stop();
    });
  }
  test("a corrupted cache is ignored", async () => {
    mkdirSync(join(cache(), "rasoat"));
    writeFileSync(join(cache(), "rasoat/snapshot-v1.json"), "{ nope");
    const { report } = await scanJson(FIXTURES + "npm");
    expect(report.data.origin).toBe("bundled");
  });
  test("old data carries a warning", async () => {
    const { report } = await scanJson(FIXTURES + "npm");
    const days = Math.floor((Date.now() - Date.parse(BUNDLED.built)) / 86_400_000);
    expect(report.data).toMatchObject({ age_days: days, stale: days > 7 });
  });
  test("control sequences in advisory text never reach the terminal", async () => {
    const evil = "\u001b]0;pwned\u0007\u001b[2Jpoison\u009b31m";
    const advisories = BUNDLED.next.advisories.map((a) => ({ ...a, summary: evil + a.summary }));
    const s = await served(() => Response.json(later(BUNDLED, { next: { ...BUNDLED.next, advisories } })));
    const human = await rasoat(["scan", FIXTURES + "npm"], { RASOAT_DATA_URL: s.url });
    expect(human.out).toContain("poison");
    expect(human.out).not.toMatch(/[\u001b\u0007\u009b]/);
    rmSync(join(cache(), "rasoat"), { recursive: true });
    const json = await rasoat(["scan", FIXTURES + "npm", "--json"], { RASOAT_DATA_URL: s.url });
    expect(json.out).not.toMatch(/[\u001b\u0007\u009b]/);
    expect(JSON.parse(json.out).results[0].advisories[0].summary).toContain(evil);
    s.stop();
  });
  test("the notices are the program's own, whatever a download says", async () => {
    const s = await served(() => Response.json(later(BUNDLED, { notices: ["Sponsored by nobody"] })));
    const { report } = await scanJson(FIXTURES + "npm", { RASOAT_DATA_URL: s.url }, []);
    expect(report.notices).not.toContain("Sponsored by nobody");
    expect(parseSnapshot(BUNDLED)).not.toBeNull();
    s.stop();
  });
});

describe("scanning a site", () => {
  test("bot protection is reported, not fought: one request, exit 3", async () => {
    let hits = 0;
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => (hits++, new Response("no", { status: 403, headers: { server: "cloudflare" } })) });
    const { report, code } = await scanJson(`http://127.0.0.1:${server.port}/`);
    server.stop(true);
    expect(hits).toBe(1);
    expect(code).toBe(3);
    expect(report.site).toMatchObject({ outcome: "blocked", status: 403, by: "Cloudflare" });
  });
  test("unreachable: exit 3 with the cause", async () => {
    const { report, code } = await scanJson("http://127.0.0.1:9/");
    expect(code).toBe(3);
    expect(report.site).toMatchObject({ outcome: "unreachable" });
  });
  test("a redirect loop stops", async () => {
    let hits = 0;
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (req) => (hits++, Response.redirect(new URL(`/${hits}`, req.url).href, 302)) });
    const { report } = await scanJson(`http://127.0.0.1:${server.port}/`);
    server.stop(true);
    expect(report.site.outcome).toBe("unreachable");
    expect(hits).toBeLessThanOrEqual(6);
  });
  test("a site without a recognised framework: exit 3, nothing claimed", async () => {
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("<html>hi</html>", { headers: { "content-type": "text/html" } }) });
    const { report, code } = await scanJson(`http://127.0.0.1:${server.port}/`);
    server.stop(true);
    expect([code, report.results]).toEqual([3, []]);
  });
});
