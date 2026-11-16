package deps

import "strings"

// cratesIO: the two forms of the crates.io registry in a Cargo.lock `source`. A path or git dependency has no `source`
// (or a git one), and an alternative registry's crate of the same name is not the crate OSV knows.
func cratesIO(source string) bool {
	return strings.Contains(source, "github.com/rust-lang/crates.io-index") || strings.Contains(source, "index.crates.io")
}

// cargoLock reads each `[[package]]` table's name, version and source. Plain lines; no TOML library.
func cargoLock(text string) []Pkg {
	var out []Pkg
	var name, version, source string
	flush := func() {
		if name != "" && version != "" && cratesIO(source) {
			out = append(out, Pkg{Eco: Cargo, Name: name, Version: version})
		}
		name, version, source = "", "", ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "["):
			flush() // "[[package]]" starts one, "[metadata]" ends them
		case strings.HasPrefix(line, "name = "):
			name = unquote(strings.TrimPrefix(line, "name = "))
		case strings.HasPrefix(line, "version = "):
			version = unquote(strings.TrimPrefix(line, "version = "))
		case strings.HasPrefix(line, "source = "):
			source = unquote(strings.TrimPrefix(line, "source = "))
		}
	}
	flush()
	return out
}
