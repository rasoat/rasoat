package deps

import "strings"

// goSum: `module v1.2.3 h1:...` is a downloaded module's source; `module v1.2.3/go.mod h1:...` only its go.mod, which
// the build graph reads without compiling it. Only the first kind is a package this project ships.
func goSum(text string) []Pkg {
	var out []Pkg
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		out = append(out, Pkg{Eco: Go, Name: f[0], Version: f[1]})
	}
	return out
}

// goMod is the fallback for a module with no go.sum: its `require` list, in a block or on one line.
func goMod(text string) []Pkg {
	var out []Pkg
	block := false
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "//")
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case block && f[0] == ")":
			block = false
		case block && len(f) >= 2:
			out = append(out, Pkg{Eco: Go, Name: f[0], Version: f[1]})
		case f[0] == "require" && len(f) == 2 && f[1] == "(":
			block = true
		case f[0] == "require" && len(f) >= 3:
			out = append(out, Pkg{Eco: Go, Name: f[1], Version: f[2]})
		}
	}
	return out
}
