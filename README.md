# rasoat

Checks the versions a project or site runs against published vulnerabilities, and says what to move to.

```
rasoat scan              # the current directory; finds every project under it
rasoat scan ~/sites      # a folder of client sites
rasoat scan example.com  # a site from outside: only what any browser downloads
rasoat scan . --json     # for CI
rasoat mcp               # for AI agents: read-only tools over stdio
```

## Install

Download the file for your platform from [the latest release](https://github.com/rasoat/rasoat/releases/latest), make it
executable, and put it on your `PATH`. Each binary is built by [this workflow](.github/workflows/release.yml) on GitHub's
runners and attested, so you can check where it came from before you run it:

```
gh attestation verify rasoat-darwin-arm64 --repo rasoat/rasoat
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Only `darwin-arm64` is run by hand before a release; the workflow runs the tests and the Linux binary's scan. From source,
with [Bun](https://bun.sh): `bun install && bun run rasoat scan .`

## Use it from an AI agent

`rasoat mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, with two read-only tools:
`scan` (the same report as `--json`) and `fix_plan` (per finding: the version to move to, whether it crosses a major
version, the runtime it needs, the file and command, the official upgrade guides). Your agent makes the change, with your
consent, and scans again. No account, and no token.

Claude Code, with the skill that teaches that loop (install the binary first, see above):

```
claude plugin marketplace add rasoat/rasoat
claude plugin install rasoat@rasoat
```

Any other MCP client:

```json
{ "mcpServers": { "rasoat": { "command": "rasoat", "args": ["mcp"] } } }
```

The skill itself is [one file](plugin/skills/rasoat/SKILL.md), if your agent reads skills another way.

What the MCP mode holds to:

- It changes nothing. It writes only its data cache, and `fix_plan` returns commands, it never runs them.
- It refuses local and private addresses, on every redirect too: an agent picks the address, perhaps from text it read. The
  terminal command still reads `localhost`, because a person chose it there.
- A version from the downloaded data reaches a command only if it is a plain version number.
- Each result says its strings are data, not instructions, and long strings are cut at 500 characters. Advisory text and
  a scanned project's files are third-party text in your agent's context all the same, so keep your agent's own approval
  prompts on.
- Tool descriptions are constants in the binary. Nothing downloaded or scanned can change them.

## What it reads

| Product | From |
|---|---|
| Next.js | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1, berry), `bun.lock`, `node_modules/next/package.json`, a `package.json` with no lockfile (reported as "not exact") |
| WordPress core | `wp-includes/version.php`, `composer.lock` (roots/wordpress, johnpbloch/wordpress) |
| Node.js, PHP, Bun | `.nvmrc`, `.node-version`, `.php-version`, `.bun-version`, `.tool-versions`, `packageManager` |

**Not checked:** WordPress plugins and themes (where most WordPress holes are), other npm or Composer packages, other
frameworks. A clean result covers only the versions it lists. Use `npm audit` or OSV-Scanner for your whole dependency tree.

## What leaves your machine

- One `GET https://rasoat.com/data/snapshot-v1.json`, at most once a day, carrying a `rasoat-cli/<version>` user agent and
  nothing about your project. `--offline` removes it: the binary carries the data from its build.
- `rasoat scan <url>` fetches that site's page and scripts, as a browser does. If bot protection answers, it reports that
  and stops.
- `rasoat mcp` sends the same things, no more.
- No account, no token, no telemetry. Your files, paths and versions are not sent anywhere.

It reads files as text and never runs project code, follows no symlink, and writes only its cache (`~/.cache/rasoat/`,
or `$XDG_CACHE_HOME/rasoat/`). A download that is malformed, older than what it has, or missing records is refused and
the report says so. The snapshot download is protected by TLS only: it is not separately signed yet.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | every version found is judged clean |
| 1 | a version is vulnerable or on an unsupported line |
| 2 | usage or internal error |
| 3 | no proof either way: nothing identified, a site unreadable, or a version that cannot be judged |

`--json` prints `schema: 1`: `results[]` (`product`, `version`, `status`, `fix`, `noFix`, `reason`, `advisories[]`,
`sources[]`), `summary`, `data`, `site`, `notes`, `not_checked`, `notices`, `exit_code`.

## Licence

The program is under the [Apache License 2.0](LICENSE). The datasets in `data/` keep their sources' terms, listed below.

## Data

Next.js: GitHub Advisory Database (CC-BY-4.0). WordPress: WordPress.org release status and NVD. Node.js: nodejs/security-wg.
PHP: NVD. Bun: its own advisories. Release lines: endoflife.date.

This product uses the NVD API but is not endorsed or certified by the NVD.

Independent project, not affiliated with Vercel, WordPress, the OpenJS Foundation, The PHP Group or Oven. Vercel, the
Vercel design, Next.js and related marks, designs and logos are trademarks or registered trademarks of Vercel, Inc. or its
affiliates in the US and other countries.
