// rasoat: which of your versions have published vulnerabilities, and what to move to. Reads files as text, runs nothing.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/hook"
	"github.com/rasoat/rasoat/internal/localdb"
	"github.com/rasoat/rasoat/internal/mcp"
	"github.com/rasoat/rasoat/internal/report"
	"github.com/rasoat/rasoat/internal/rules"
	"github.com/rasoat/rasoat/internal/scan"
)

func help() string {
	return report.Tool + " " + report.Version + ` - check your versions against published vulnerabilities

Usage:
  ` + report.Tool + ` scan [dir|url]   default: the current directory
  ` + report.Tool + ` host             this Linux machine: distro release, kernel, installed packages
  ` + report.Tool + ` discover [dir]    list every component a directory names and which data judges it; judges nothing, sends nothing
  ` + report.Tool + ` db status        the data files in the cache: built, records, age (reads the cache, sends nothing)
  ` + report.Tool + ` db update        download the data files now, so --offline judges from them (--all: every distro release too)
  ` + report.Tool + ` rules check [dir] validate your rules.json and show what each rule matches in a directory (offline)
  ` + report.Tool + ` hook <event>      for the Claude Code plugin: session-start or post-tool-use; reads the hook JSON on stdin, prints context or nothing, always exits 0
  ` + report.Tool + ` mcp              serve the read-only tools scan, fix_plan, host, discover and db_status to an AI agent over stdio

Options:
  --json        print the report as JSON (schema 1)
  --offline     do not download advisory data; use what is already here
  --all         list every advisory, not the worst 5; db update: also every distro release file
  --lang vi|en  default: from LANG
  --root DIR    host: read a mounted image or container tree instead of this machine
  --name LABEL  host: the name to report as target instead of the --root path
  --kernel V    host: judge this kernel version instead of the running one
  --rules FILE  your own detectors (default: $XDG_CONFIG_HOME/rasoat/rules.json or ~/.config/rasoat/rules.json); never read from a scanned directory
  -h, --help    -v, --version

Reads:   lockfiles (npm, pnpm, yarn, bun, Cargo.lock, go.sum or go.mod: every package is judged), wp-includes/version.php,
         composer.lock, version pin files, Dockerfile FROM, compose image:, CI runtime pins. As text; it never runs project code.
         host: /etc/os-release and the dpkg, rpm or apk database. It runs no command and needs no root.
Sends:   discover and db status send nothing. db update: one GET for each data file it names, never a project or a package.
         one GET for the advisory data, at most once a day, with no project information in it. For each ecosystem a
         project uses (npm, crates.io, Go) one more GET of that ecosystem's file, named by ecosystem, never by package;
         images in a directory add a GET for the release lines, also with none.
         A URL scan fetches that site's public page and scripts, as a browser does.
         host: GETs for the data of this distro release, naming the release, never your packages.
         your rules file, if there is one. hook: the hook JSON on stdin.
Writes:  only its data cache, ~/.cache/rasoat/ (hook keeps a small baseline of findings there).
Exit:    0 all clean, 1 vulnerable or unsupported, 2 usage or error, 3 nothing or not everything could be judged.

` + strings.Join(core.NOTICES, "\n") + "\n"
}

type options struct {
	json, offline, all, help, version bool
	lang, root, kernel, rules, name   string
	positionals                       []string
}

func parse(args []string) (options, error) {
	var o options
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			o.json = true
		case a == "--offline":
			o.offline = true
		case a == "--all":
			o.all = true
		case a == "-h" || a == "--help":
			o.help = true
		case a == "-v" || a == "--version":
			o.version = true
		case a == "--lang":
			i++
			if i == len(args) {
				return o, errors.New("--lang needs a value")
			}
			o.lang = args[i]
		case strings.HasPrefix(a, "--lang="):
			o.lang = strings.TrimPrefix(a, "--lang=")
		case a == "--name" || strings.HasPrefix(a, "--name="):
			v := strings.TrimPrefix(a, "--name=")
			if a == "--name" {
				if i++; i == len(args) {
					return o, errors.New("--name needs a value")
				}
				v = args[i]
			}
			if v == "" || utf8.RuneCountInString(v) > 100 || strings.ContainsFunc(v, unicode.IsControl) {
				return o, errors.New("--name needs 1 to 100 characters, none of them a control character")
			}
			o.name = v
		case a == "--root" || a == "--kernel" || a == "--rules":
			i++
			if i == len(args) {
				return o, fmt.Errorf("%s needs a value", a)
			}
			switch a {
			case "--root":
				o.root = args[i]
			case "--kernel":
				o.kernel = args[i]
			default:
				o.rules = args[i]
			}
		case strings.HasPrefix(a, "--root="):
			o.root = strings.TrimPrefix(a, "--root=")
		case strings.HasPrefix(a, "--kernel="):
			o.kernel = strings.TrimPrefix(a, "--kernel=")
		case strings.HasPrefix(a, "--rules="):
			o.rules = strings.TrimPrefix(a, "--rules=")
		case a == "--":
			o.positionals = append(o.positionals, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "-") && a != "-":
			return o, fmt.Errorf("Unknown option '%s'", a)
		default:
			o.positionals = append(o.positionals, a)
		}
	}
	return o, nil
}

// db is `rasoat db status` and `rasoat db update`: the local vulnerability database.
func db(o options, lang string) int {
	if o.positionals[1] == "status" {
		s := localdb.Inspect()
		if o.json {
			fmt.Println(report.JSON(s))
		} else {
			fmt.Println(localdb.RenderStatus(s, lang))
		}
		return 0
	}
	var announce func(localdb.Plan)
	if !o.json {
		announce = func(p localdb.Plan) { fmt.Println(localdb.RenderPlan(p, lang)) }
	}
	u := localdb.Update(o.all, scan.UserAgent, announce)
	if o.json {
		fmt.Println(report.JSON(u))
	} else {
		fmt.Println(localdb.RenderUpdate(u, lang))
	}
	return u.ExitCode
}

// runHook answers a Claude Code hook. It exits 0 whatever happens: a hook must never block or fail a session.
func runHook(event string) int {
	if event != hook.SessionStart && event != hook.PostToolUse {
		fmt.Fprintln(os.Stderr, "unknown hook event: "+event)
		return 0
	}
	var in io.Reader = os.Stdin
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice != 0 {
		in = strings.NewReader("") // run by hand: no hook JSON to wait for
	}
	hook.Run(event, in, os.Stdout)
	return 0
}

func run(args []string) int {
	o, err := parse(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if o.version {
		fmt.Println(report.Version)
		return 0
	}
	if o.help {
		fmt.Print(help())
		return 0
	}
	if len(o.positionals) == 0 {
		fmt.Print(help())
		return 2
	}
	command := o.positionals[0]
	if command == "mcp" && len(o.positionals) == 1 {
		return mcp.Serve(os.Stdin, os.Stdout)
	}
	if command == "hook" && len(o.positionals) == 2 {
		return runHook(o.positionals[1])
	}
	known := (command == "scan" && len(o.positionals) <= 2) || (command == "host" && len(o.positionals) == 1) ||
		(command == "discover" && len(o.positionals) <= 2) ||
		(command == "rules" && (len(o.positionals) == 2 || len(o.positionals) == 3) && o.positionals[1] == "check") ||
		(command == "db" && len(o.positionals) == 2 && (o.positionals[1] == "status" || o.positionals[1] == "update"))
	if !known {
		fmt.Fprint(os.Stderr, help())
		return 2
	}
	if o.lang != "" && o.lang != "vi" && o.lang != "en" {
		fmt.Fprintln(os.Stderr, "--lang must be vi or en")
		return 2
	}
	lang := o.lang
	if lang == "" {
		lang = report.LangFromEnv()
	}
	print := func(rep *report.Report) int {
		if o.json {
			fmt.Println(report.JSON(rep))
		} else {
			fmt.Println(report.Render(rep, lang, o.all))
		}
		return rep.ExitCode
	}
	if command == "db" {
		return db(o, lang)
	}
	if command == "rules" {
		return rulesCommand(o)
	}
	rs, err := rules.Load(o.rules)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if command == "discover" {
		target := "."
		if len(o.positionals) == 2 {
			target = o.positionals[1]
		}
		inv, err := scan.Discover(target, true, rs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		if o.json {
			fmt.Println(report.JSON(inv))
		} else {
			fmt.Println(report.RenderInventory(inv, lang))
		}
		return 0
	}
	if command == "host" {
		rep, err := scan.Host(scan.HostOptions{Root: o.root, Kernel: o.kernel, Name: o.name, Offline: o.offline})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return print(rep)
	}
	target := "."
	if len(o.positionals) == 2 {
		target = o.positionals[1]
	}
	rep, _, err := scan.Target(target, o.offline, false, rs)
	if err != nil {
		var nt *scan.NotATarget
		if errors.As(err, &nt) {
			fmt.Fprintln(os.Stderr, nt)
			return 2
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	return print(rep)
}

func main() { os.Exit(run(os.Args[1:])) }
