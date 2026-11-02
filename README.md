# rasoat

Checks the versions a project, a site or a Linux machine runs against published vulnerabilities, and says what to move to.

```
rasoat scan              # the current directory; finds every project under it
rasoat scan ~/sites      # a folder of client sites
rasoat scan example.com  # a site from outside: only what any browser downloads
rasoat scan . --json     # for CI
rasoat host              # this Linux machine: distro release, kernel, installed packages
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

One static file of about 8 MB, with no dependency and no runtime to install. Built for Linux (x64, arm64, armv7, 386, riscv64,
ppc64le, s390x), macOS (arm64, x64), Windows (x64, arm64) and FreeBSD (x64). The workflow runs the whole test suite on Linux,
macOS and Windows, on x64 and arm64, before it builds; armv7, 386, riscv64, ppc64le, s390x and FreeBSD are built, not run.

It uses your machine's trust store. A machine with none, such as a minimal container image, falls back to Mozilla's root
certificates carried in the binary.

From source, with [Go](https://go.dev) and nothing else: `go run . scan .`. `go.mod` has no dependency.

## Use it from an AI agent

`rasoat mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, with three read-only tools:
`scan` (the same report as `--json`), `fix_plan` (per finding: the version to move to, whether it crosses a major version,
the runtime it needs, the file and command, the official upgrade guides) and `host` (this Linux machine, and the upgrade
command it does not run). Your agent makes the change, with your consent, and scans again. No account, and no token.

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

## A Linux machine

```
rasoat host                       # this machine. It needs no root, and runs no command
rasoat host --all --json          # every finding, for a script
rasoat host --root /mnt/image     # a mounted image or an extracted container tree, from any OS
rasoat host --kernel 6.6.30       # a kernel you name, instead of the running one
```

| Judged | How |
|---|---|
| Distro release | `/etc/os-release` against [endoflife.date](https://endoflife.date): past its end, it is `unsupported` |
| Installed packages | The package database, read as a file (dpkg; rpm in its SQLite, Berkeley DB and NDB formats; apk), against the fixes the distro published. A package is `vulnerable` when its distro has published a fix and the installed version is below it |
| Kernel | A distro kernel by its distro's own package data, never by its number: backports make the number say nothing. A plain kernel.org number by [kernel.org's CVE records](https://git.kernel.org/pub/scm/linux/security/vulns.git). A vendor's build no package explains is `unknown` |
| Reboot | A newer kernel is installed than is running |

Per-package advisories: Ubuntu, Debian, RHEL, AlmaLinux, Rocky Linux, Alpine, openSUSE Leap and Tumbleweed, SLES. CentOS,
Fedora, Amazon Linux and Oracle Linux get their end of life judged and a note that their packages were not. Arch, and
derivatives such as Linux Mint or Kali, are `unknown`: another distro's advisories would misjudge their builds.

**Limits, measured.** In a container the kernel is the host's, so it is not judged. Advisories with no fix yet are a count,
not findings. The kernel upstream check does not know your configuration: most CVEs in a driver you do not load do not reach
you. The data comes through OSV, which can lag a distro by days: in our comparison with Trivy on 19 images (575
vulnerable packages, 571 in common), the only fixes we missed were ones OSV had not yet published. Paid extended support (Ubuntu Pro, Debian ELTS) is not seen.

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
- `rasoat host` sends two or three GETs to this repository's release files, at most once a day, each naming only your distro
  release (`debian-12.tsv.gz`), never a package. `--offline` removes them, and then needs a previous run's cache.
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
| 3 | no proof either way: nothing identified, a site unreadable, no data, or a version that cannot be judged |

`--json` prints `schema: 1`: `results[]` (`product`, `version`, `status`, `fix`, `noFix`, `reason`, `advisories[]`,
`sources[]`), `summary`, `data`, `site`, `notes`, `not_checked`, `notices`, `exit_code`.

A `host` report also has `host` (`distro`, `packages`, `open_no_fix`, `kernel_running`, `kernel_newest`, `reboot_needed`,
`in_container`, `upgrade_command`), and `target.kind` is `host`.

## Licence

The program is under the [Apache License 2.0](LICENSE). The datasets keep their sources' terms, listed below.

## Data

Next.js: GitHub Advisory Database (CC-BY-4.0). WordPress: WordPress.org release status and NVD. Node.js: nodejs/security-wg.
PHP: NVD. Bun: its own advisories. Release lines: endoflife.date. Linux: [OSV.dev](https://osv.dev) exports of each distro's
security data, reduced to package, id, fixed version and severity, with no advisory text (each record links to its source);
upstream kernel: kernel.org CVE records. Rebuilt daily by [this workflow](.github/workflows/linux-data.yml), as files of their
own on [the linux-data release](https://github.com/rasoat/rasoat/releases/tag/linux-data), which this program downloads and
does not contain. Each file's first line names its source and terms: Ubuntu and Alpine files are CC-BY-SA-4.0, Red Hat
CC-BY-4.0, AlmaLinux MIT, Rocky Linux BSD, kernel.org the CVE Terms of Use; Debian and SUSE as those projects publish them.

This product uses the NVD API but is not endorsed or certified by the NVD.

Independent project, not affiliated with Vercel, WordPress, the OpenJS Foundation, The PHP Group, Oven, or any Linux
distribution. Linux is a registered trademark of Linus Torvalds. Vercel, the
Vercel design, Next.js and related marks, designs and logos are trademarks or registered trademarks of Vercel, Inc. or its
affiliates in the US and other countries.
