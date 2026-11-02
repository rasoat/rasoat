// rasoat: which of your versions have published vulnerabilities, and what to move to. Reads files as text, runs nothing.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/mcp"
	"github.com/rasoat/rasoat/internal/report"
	"github.com/rasoat/rasoat/internal/scan"
)

func help() string {
	return report.Tool + " " + report.Version + ` - check your versions against published vulnerabilities

Usage:
  ` + report.Tool + ` scan [dir|url]   default: the current directory
  ` + report.Tool + ` host             this Linux machine: distro release, kernel, installed packages
  ` + report.Tool + ` mcp              serve the read-only tools scan, fix_plan and host to an AI agent over stdio

Options:
  --json        print the report as JSON (schema 1)
  --offline     do not download advisory data; use what is already here
  --all         list every advisory, not the worst 5
  --lang vi|en  default: from LANG
  --root DIR    host: read a mounted image or container tree instead of this machine
  --kernel V    host: judge this kernel version instead of the running one
  -h, --help    -v, --version

Reads:   lockfiles, wp-includes/version.php, composer.lock, version pin files. As text; it never runs project code.
         host: /etc/os-release and the dpkg, rpm or apk database. It runs no command and needs no root.
Sends:   one GET for the advisory data, at most once a day, with no project information in it.
         A URL scan fetches that site's public page and scripts, as a browser does.
         host: GETs for the data of this distro release, naming the release, never your packages.
Writes:  only its data cache, ~/.cache/rasoat/.
Exit:    0 all clean, 1 vulnerable or unsupported, 2 usage or error, 3 nothing or not everything could be judged.

` + strings.Join(core.NOTICES, "\n") + "\n"
}

type options struct {
	json, offline, all, help, version bool
	lang, root, kernel                string
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
		case a == "--root" || a == "--kernel":
			i++
			if i == len(args) {
				return o, fmt.Errorf("%s needs a value", a)
			}
			if a == "--root" {
				o.root = args[i]
			} else {
				o.kernel = args[i]
			}
		case strings.HasPrefix(a, "--root="):
			o.root = strings.TrimPrefix(a, "--root=")
		case strings.HasPrefix(a, "--kernel="):
			o.kernel = strings.TrimPrefix(a, "--kernel=")
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
	if !(command == "scan" && len(o.positionals) <= 2) && !(command == "host" && len(o.positionals) == 1) {
		fmt.Fprint(os.Stderr, help())
		return 2
	}
	if o.lang != "" && o.lang != "vi" && o.lang != "en" {
		fmt.Fprintln(os.Stderr, "--lang must be vi or en")
		return 2
	}
	print := func(rep *report.Report) int {
		lang := o.lang
		if lang == "" {
			lang = report.LangFromEnv()
		}
		if o.json {
			fmt.Println(report.JSON(rep))
		} else {
			fmt.Println(report.Render(rep, lang, o.all))
		}
		return rep.ExitCode
	}
	if command == "host" {
		rep, err := scan.Host(o.root, o.kernel, o.offline)
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
	rep, _, err := scan.Target(target, o.offline, false)
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
