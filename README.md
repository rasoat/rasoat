# rasoat

Checks the versions a project, a site or a Linux machine runs against published vulnerabilities, and says what to move to.

```
rasoat scan              # the current directory; finds every project under it
rasoat scan ~/sites      # a folder of client sites
rasoat scan example.com  # a site from outside: only what any browser downloads
rasoat scan . --json     # for CI
rasoat host              # this Linux machine: distro release, kernel, installed packages
rasoat discover          # what the directory names, and which data judges each part; judges nothing, sends nothing
rasoat db status         # the data files in the cache: built, records, age
rasoat db update         # download them now, so --offline judges from them
rasoat rules check       # validate your rules.json and show what each rule matches here
rasoat hook <event>      # for the Claude Code plugin (session-start, post-tool-use)
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

`rasoat mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, with five read-only tools:
`scan` (the same report as `--json`), `fix_plan` (per finding: the version to move to, whether it crosses a major version,
the runtime it needs, the file and command, the official upgrade guides), `host` (this Linux machine, and the upgrade
command it does not run), `discover` (the inventory of a directory: what it names and which data judges it, with lockfile packages
counted, not listed) and `db_status` (the data files this machine holds). Your agent makes the change, with your
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
- It has no tool that updates the data: `discover` and `db_status` read files and send nothing, and an agent cannot start a
  download beyond what `scan` itself does. `rasoat db update` is for a person at a terminal.
- It refuses local and private addresses, on every redirect too: an agent picks the address, perhaps from text it read. The
  terminal command still reads `localhost`, because a person chose it there.
- A version from the downloaded data reaches a command only if it is a plain version number.
- Each result says its strings are data, not instructions, and long strings are cut at 500 characters. Advisory text and
  a scanned project's files are third-party text in your agent's context all the same, so keep your agent's own approval
  prompts on.
- Tool descriptions are constants in the binary. Nothing downloaded or scanned can change them.

`fix_plan` gives a package from a lockfile the command its lockfile's manager uses, run in the directory of that lockfile:
`npm install <name>@<v>`, `pnpm update <name>@<v>`, `yarn up <name>@<v>` (berry) or `yarn upgrade <name>@<v>` (v1),
`bun update <name>@<v>`, `cargo update -p <name>@<current> --precise <v>`, `go get <module>@v<v> && go mod tidy`. A package
that the `package.json` beside the lockfile does not list is pulled in by another: `command` is null and `how` says which
`overrides` or `resolutions` entry pins it (or to update the package that depends on it). An image is a line edit, so `command`
is null and `how` names the file and the `image:` or `FROM` line. A package name reaches a command only if it has the plain
shape its ecosystem allows, and a version only if it is a plain version number.

## What is in a directory, and the local data

```
rasoat discover [dir]       # every component the scan would see, and what judges it. Walks files only: no network, no cache
rasoat discover . --json    # the same, with every lockfile package listed
rasoat db status            # the data files in the cache: built date, records, age, stale, path. Reads the cache only
rasoat db update            # download the snapshot, the release-line index and the npm, crates.io and Go files now
rasoat db update --all      # and every distro release file the index lists
```

`discover` judges nothing. Each component has a `kind` (`pin`: a version a file states, a version file or a CI pin; `image`;
`package`: one package a lockfile resolves), a `product`, a `version` (null when the file names none), `where` (the file) and
`judged_by`: the data that judges it, `snapshot` (Next.js, WordPress, Node.js, PHP, Bun), `lines` (the image and CI-pin
families: end of life only), `advisories` (an exact tag of nginx, Apache httpd, Caddy or Traefik: the vendor's advisories; a floating tag of these is judged by `lines`), `eco-npm`, `eco-cargo` or `eco-go`; or **null** when no data does. The null ones are what a
scan cannot cover. An image outside the family table lists the tag as written as its version; a reference with a variable in
it is listed with `unresolved: true`. In the terminal, packages are counted per ecosystem and not listed.

`discover --json` prints `schema: 1`, `kind: "inventory"`: `target`, `summary` (`components`, `judged`, `not_judged`,
`packages` per ecosystem), `items[]` (`kind`, `product`, `version`, `where`, `judged_by`, and `ref` and `unresolved` when they
apply), `notes`, `notices`. A scan report has the same items for what no data judged, as `not_judged[]` (images outside the
family table and unresolved references), next to the `notes` it always had. The MCP tool lists no packages, only their count.

`db status` is one row per file the CLI can use: the rasoat.com snapshot (`records` are its advisories), the release-line
index (`records` are the files it lists), each of `eco-npm`, `eco-cargo`, `eco-go`, and each distro file already cached.
`stale` is the rule a scan warns by: more than 7 days old. `db update` downloads each file through the same code a scan
uses and holds it to the same checks: a file older than the cached one, or with 10% fewer records, is refused and the cached
one kept (`kept`, with the reason, exit 2). The index carries no file sizes, so `--all` says how many files and how many
records before it downloads them. After `db update --all`, `--offline` judges everything it can judge, anywhere. A default
`scan` or `host` still downloads at most once a day, as before.

## Your own rules

`discover` and `scan` cover what the built-in tables cover. For what they do not, write a rules file: your own detectors, in
`$XDG_CONFIG_HOME/rasoat/rules.json` or `~/.config/rasoat/rules.json` (or `--rules FILE`). **Only you supply rules: a project
you scan cannot.** A `rules.json` inside a scanned directory is an ordinary file, because a repository you scan must not change
how it is judged. Nothing is uploaded, and the file is checked before it is used: an unknown key, a bad pattern or a wrong
product is an error that names it (exit 2).

```json
{ "version": 1,
  "images": { "grafana/loki": "family:loki", "minio/minio": "none", "axllent/mailpit": "none" },
  "detectors": [
    { "name": "app-version", "files": ["VERSION", "*.version"], "regex": "^(\\d+\\.\\d+\\.\\d+)$", "product": "pkg:npm/my-lib" }
  ] }
```

- `images` says what an image the built-in table does not know is, by its name without registry or tag. `family:<id>` is judged
  by release lines, when the id is one the release-line index carries (the families `discover` lists as `lines`); any other id
  stays `not judged` and a note says so. `none` means no data judges it and you know: it is listed, marked `acknowledged`, and
  leaves `not_judged`. An image the built-in table already knows is judged by the table.
- `detectors` read a version from files. `files` are names or globs matched on a file's name (no `/`), found by the same walk as
  every other file: text only, no symlink, at most 1 MB, nothing under `node_modules`, `vendor` or a hidden directory. `regex` is
  [RE2](https://github.com/google/re2/wiki/Syntax) with exactly one capture group, matched line by line; what it captures must be
  a plain version. `product` is `family:<id>` (judged by release lines, or the verdict of Node.js, PHP, Bun, WordPress), `pkg:npm/<name>`,
  `pkg:cargo/<name>` or `pkg:golang/<module>` (judged against that ecosystem's advisories, as a lockfile package is), or `none`.
- `judged_by` names the rule: `rule:app-version → eco-npm`, `rule:image:grafana/loki → lines`. `discover --json` adds `rule`,
  and `acknowledged` where it applies; `summary.acknowledged` counts them.
- `rasoat rules check [dir]` validates the file and prints, for each rule, what it matches in the directory (default: the current
  one). It walks files and sends nothing. The MCP tools read the same file; there is no tool to write it.

## In Claude Code: hooks

The plugin has two hooks. Each runs this binary and nothing else, and **neither can block or fail a session**: whatever goes
wrong, they print nothing and exit 0. If `rasoat` is not on `PATH`, Claude Code shows its usual "hook error" notice and goes on.

```
rasoat hook session-start    # reads Claude Code's hook JSON on stdin (its cwd)
rasoat hook post-tool-use
```

- **Session start.** If the directory holds anything `discover` sees, it scans it the normal way (the usual download rule: at
  most once a day; if that takes over 15 seconds it falls back to the data already here) and puts one line in the model's
  context: `rasoat: 1,973 components in app; 65 vulnerable, 1 unsupported, 3 not judged; data 2026-11-16. Ask before upgrading;
  the rasoat skill has the loop.` The findings are kept as the baseline for that directory.
- **After a change.** After an Edit, Write or MultiEdit of a file the walk reads (lockfiles, `package.json`, `Cargo.toml`,
  `go.mod`, a Dockerfile, a compose file, a workflow, a version pin file, or a file one of your detectors names), or a Bash command
  that changes packages (`npm|pnpm|yarn|bun install|add|remove|update`, `cargo add|update|remove`, `go get`, `go mod tidy`,
  `docker compose pull`), it rescans that project **offline** (a hook never downloads after the first line) and says something only
  when the set of vulnerable or unsupported `product@version` changed: `rasoat: after this change: 2 new (pkg:npm/x@1.2.3 critical,
  ...), 1 fixed (...).` The first check of a directory the session did not start in says how many findings it has, once.
- **State.** `~/.cache/rasoat/hook/<sha256 of the directory>.json`: product, version and status of each finding, no path and no
  file content. Names it prints come from your lockfiles, are stripped of control characters and cut short.

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

**Vendor builds.** A vendor repo (Sury, PGDG, NodeSource, MariaDB, Proxmox, Docker) ships builds under the distro's own
package names, and its version number says nothing about the distro's fixes, so such a package is never compared with them.
Origin is read from files, and nothing runs. On Debian and Ubuntu, each plain `/var/lib/apt/lists/*_Packages` is paired
with its `InRelease` or `Release`, and the `Origin:` there (never the mirror's name) says whose archive lists the exact
installed version: `Ubuntu` or `Debian` is the distro's, any other origin is a vendor's. A version listed only in a
`-backports` suite is the distro's build outside its security data and is not judged either. On rpm, the header's Vendor
tag does the same (Red Hat, AlmaLinux, Rocky, SUSE, Amazon, Oracle, Fedora, CentOS are the distros'). When the lists cannot
decide (absent, compressed as docker images keep them, or the version no longer listed), the version string does: `deb.sury.org`,
`pgdg`, `nodesource`, `+maria~`, `+pmx`, `remi`; a package nothing flags stays the distro's. apk packages are not
checked for origin. A vendor package is then judged as the product it is, one row per product and upstream version: Sury
`php8.x` and Remi `php` by the PHP verdict, NodeSource `nodejs` by the Node.js verdict, PGDG `postgresql-NN` and MariaDB's
`mariadb` by their release line (`unknown`, never `ok`: that data knows when a line ends, not its flaws). Every other vendor
package is counted in a `vendor-not-judged:<origin>:<count>` note.

**Limits, measured.** In a container the kernel is the host's, so it is not judged. Advisories with no fix yet are a count,
not findings. The kernel upstream check does not know your configuration: most CVEs in a driver you do not load do not reach
you. The data comes through OSV, which can lag a distro by days: in our comparison with Trivy on 19 images (575
vulnerable packages, 571 in common), the only fixes we missed were ones OSV had not yet published. Paid extended support (Ubuntu Pro, Debian ELTS) is not seen.

### Pull mode

To judge a machine without installing anything on it, run `scripts/host-files.sh` there. It is POSIX sh and awk, runs no
rasoat, and writes a tar to stdout of only the files `rasoat host` reads: os-release, the package database, and for apt
each release file cut to its header and each Packages list cut to the installed packages. It is small enough to move
over a slow link, and the answer is the same as on the whole tree.

```
ssh host 'sh -s' < scripts/host-files.sh > host.tar
mkdir t && tar -xf host.tar -C t
rasoat host --root t --name LABEL      # LABEL names the machine in the report instead of the path
```

`sh scripts/host-files.sh /mnt/image > host.tar` does the same for a mounted image. Compressed apt lists (`.lz4`) are
skipped, as `host` does not read them.

## What it reads

| Product | From |
|---|---|
| Next.js | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1, berry), `bun.lock`, `node_modules/next/package.json`, a `package.json` with no lockfile (reported as "not exact") |
| WordPress core | `wp-includes/version.php`, `composer.lock` (roots/wordpress, johnpbloch/wordpress) |
| Node.js, PHP, Bun | `.nvmrc`, `.node-version`, `.php-version`, `.bun-version`, `.tool-versions`, `packageManager`; a Dockerfile's `FROM node:22.3.0` or `oven/bun:1.4.4`, a compose `image:`, a workflow's `node-version`, `bun-version`, `php-version`. These get the verdict a pin file gets, and the row's source names the file and the reference (`Dockerfile (oven/bun:1.4.4)`) |
| Container images and CI pins | `FROM` in `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile` (build stages and `scratch` skipped; an `ARG NAME=default` before the first `FROM` fills `${NAME}`), `image:` in `docker-compose*.yml` and `compose*.yaml` (`${X:-default}` filled), and `go-version`, `python-version` (a list gives each item) in `.github/workflows/*.yml`. A variable with no literal value is reported as a note, never guessed |
| Every npm package | the same five lockfiles (`bun.lockb` is binary and is reported as not read). Next.js keeps its own verdict above |
| Every crate | `Cargo.lock`: crates from crates.io only; path and git dependencies are not on any advisory list |
| Every Go module | `go.sum` (the modules downloaded), or `go.mod`'s `require` list when there is no `go.sum` |

**Images and pins, how they are judged.** The product name in a row is the [endoflife.date](https://endoflife.date) id of
its family, so `postgres`, `timescale/timescaledb:2.32.0-pg17` and `pgvector/pgvector:0.8.7-pg17` are all `postgresql`
(by the PostgreSQL major the tag names), and `golang` is `go`: PostgreSQL, Redis, nginx, MariaDB, MySQL, ClickHouse,
Caddy, Apache httpd (`httpd`), MongoDB, RabbitMQ, Debian, Ubuntu, Alpine Linux, Python, Go, Rust, Grafana, Prometheus, Meilisearch, Traefik.
This data has release lines, not advisories, so for these a row is never `ok`, except nginx, Apache httpd, Caddy and Traefik, whose exact tags are judged against the vendor's advisories:

| Tag | Result |
|---|---|
| its line has ended (`postgres:13`, `redis:7.2.4`) | `unsupported`, with the latest release of a supported line as the fix |
| an exact release on a supported line (`postgres:16.4`) | `unknown`, reason `no-advisory-data`: no one has checked that release for flaws; `fix` is the line's latest when the tag is below it |
| a line (`postgres:16-alpine`, `redis:7`, `rust:1-bookworm`) | `unknown`, `version-not-exact`: only its end of life is judged |
| a Linux release (`debian:bookworm-slim`, `ubuntu:22.04`) | `unknown`, `distro-release-supported`: its packages are not judged here; `rasoat host --root` judges an extracted tree |
| `latest`, `stable`, no tag, a digest only | `unknown`, `image-tag-unpinned` |
| an image in no family (`axllent/mailpit`, a private name) | listed in `notes` as `image-not-judged:<file> (<image>)`, not a row |

An exact tag is one with a patch part (`1.24.0-alpine3.19`; `16.4` for PostgreSQL). Because an `unknown` row exits 3 (below), a
project that runs PostgreSQL or Redis from an image exits 3 until a data source for flaws in those exists.

Packages are judged against [OSV.dev](https://osv.dev) records (GitHub Advisory Database, RustSec, the Go vulnerability
database, and OpenSSF's malicious-package reports) reduced to a file per ecosystem: a package is `vulnerable` when a range
`introduced <= version < fixed` (or `<= last_affected`) holds. Each is one result, `pkg:npm/<name>`, `pkg:cargo/<name>` or
`pkg:golang/<module>`, with the lowest later version no advisory reaches as `fix`, or `noFix`. A malicious package has no fix
but removal. RustSec's "unmaintained" notices are left out: an abandoned crate is a warning, not a hole. Clean packages are
counted in the summary, not listed: a monorepo has 1,500. With no data to judge by (offline with no cache) the report is
`unknown` and the exit code 3, never clean.

**Not checked:** WordPress plugins and themes (where most WordPress holes are), dependencies in other ecosystems (PyPI,
RubyGems, Composer, Maven), other frameworks. A clean result covers only the versions it lists.

## What leaves your machine

- One `GET https://rasoat.com/data/snapshot-v1.json`, at most once a day, carrying a `rasoat-cli/<version>` user agent and
  nothing about your project. `--offline` removes it: the binary carries the data from its build.
- `rasoat scan <dir>` that names an image or CI pin of a family above also sends one GET for `index.json`, the release
  lines, in the same place and at most once a day. It names nothing about the project, and a directory without images does
  not send it.
- `rasoat scan <url>` fetches that site's page and scripts, as a browser does. If bot protection answers, it reports that
  and stops.
- `rasoat scan` of a directory with lockfiles sends one GET per ecosystem it found (`eco-npm.tsv.gz`, `eco-cargo.tsv.gz`,
  `eco-go.tsv.gz`, 0.06 to 2.8 MB), at most once a day: the file's name says which ecosystem, never which package. The
  packages are looked up in the file on your machine.
- `rasoat host` sends two or three GETs to this repository's release files, at most once a day, each naming only your distro
  release (`debian-12.tsv.gz`), never a package. `--offline` removes them, and then needs a previous run's cache.
- `rasoat db update` sends one GET for each file it names: the snapshot, `index.json`, the three ecosystem files and, with
  `--all`, each distro release file. Names of files, never of a project or a package. `rasoat discover` and `rasoat db status`
  send nothing.
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

`discover` and `db status` exit 0 (2 on a usage error); `db update` exits 2 when any file was kept for a problem.

`--json` prints `schema: 1`: `results[]` (`product`, `version`, `status`, `fix`, `noFix`, `reason`, `advisories[]`,
`sources[]`), `summary`, `data`, `site`, `notes`, `not_judged`, `not_checked`, `notices`, `exit_code`.

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
