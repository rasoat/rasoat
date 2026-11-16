package deps

import (
	"encoding/json"
	"sort"
	"strings"
)

// registryTarball: a package from a registry resolves to .../name/-/name-1.2.3.tgz. A git URL, a file path or a link does
// not, and its name says nothing about the registry's package of that name.
func registryTarball(resolved string) bool {
	return resolved == "" || strings.Contains(resolved, "/-/")
}

type lockEntry struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
}

// v1Entry nests its dependencies; in v2 and v3 an entry's "dependencies" is a name-to-range map, a different thing.
type v1Entry struct {
	lockEntry
	Dependencies map[string]*v1Entry `json:"dependencies"`
}

// packageLock reads npm's v2/v3 `packages` (every nested copy, the name from the last node_modules/ in the key) and v1
// `dependencies` (recursive).
func packageLock(text string) []Pkg {
	var lock struct {
		Packages     map[string]*lockEntry `json:"packages"`
		Dependencies map[string]*v1Entry   `json:"dependencies"`
	}
	if json.Unmarshal([]byte(text), &lock) != nil {
		return nil
	}
	var out []Pkg
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := lock.Packages[k]
		i := strings.LastIndex(k, "node_modules/")
		if e == nil || i < 0 || e.Link || !registryTarball(e.Resolved) {
			continue // the root, a workspace folder or a link
		}
		name := k[i+len("node_modules/"):]
		if e.Name != "" {
			name = e.Name // an alias: the key is the alias, name is the package
		}
		out = append(out, Pkg{Eco: NPM, Name: name, Version: e.Version})
	}
	var walk func(map[string]*v1Entry)
	walk = func(m map[string]*v1Entry) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			e := m[n]
			if e == nil {
				continue
			}
			name, version := n, e.Version
			if strings.HasPrefix(version, "npm:") { // "npm:real@1.2.3"
				name, version = splitSpec(n + "@" + version)
			}
			if registryTarball(e.Resolved) {
				out = append(out, Pkg{Eco: NPM, Name: name, Version: version})
			}
			walk(e.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return out
}

// pnpmLock reads the `packages:` section, the one place every locked package has a key: `name@1.2.3` (v9), `/name@1.2.3(peer@1)`
// (v6) or `/name/1.2.3_peer` (v5).
func pnpmLock(text string) []Pkg {
	var out []Pkg
	in := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" && line[0] != ' ' && line[0] != '#' {
			in = line == "packages:"
			continue
		}
		if !in || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") || !strings.HasSuffix(line, ":") {
			continue
		}
		key := strings.Trim(strings.TrimSuffix(strings.TrimSpace(line), ":"), `'"`)
		key = strings.TrimPrefix(key, "/")
		if i := strings.Index(key, "("); i > 0 {
			key = key[:i] // the peer suffix
		}
		// v5 is /name/1.2.3_peers: the part after the last slash starts with a digit and has no @ before its peers.
		if slash := strings.LastIndex(key, "/"); slash > 0 {
			if version, _, _ := strings.Cut(key[slash+1:], "_"); !strings.Contains(version, "@") && version != "" && version[0] >= '0' && version[0] <= '9' {
				out = append(out, Pkg{Eco: NPM, Name: key[:slash], Version: version})
				continue
			}
		}
		name, version := splitSpec(key)
		out = append(out, Pkg{Eco: NPM, Name: name, Version: version})
	}
	return out
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }

// yarnLock reads v1 (`"name@^1", name@^1.2:` then `  version "1.2.3"`) and berry (`  resolution: "name@npm:1.2.3"`).
func yarnLock(text string) []Pkg {
	berry := strings.Contains(text, "\n__metadata:")
	var out []Pkg
	name, resolved := "", ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "" || line[0] == '#':
		case line[0] != ' ':
			name, resolved = "", ""
			if !strings.HasSuffix(line, ":") || berry {
				continue
			}
			first, _, _ := strings.Cut(strings.TrimSuffix(line, ":"), ",")
			spec := unquote(first)
			if i := strings.Index(spec[min(1, len(spec)):], "@"); i >= 0 {
				name = spec[:i+1]
				if rng := spec[i+2:]; strings.HasPrefix(rng, "npm:") { // an alias: the range names the package
					name, _ = splitSpec(rng)
				}
			}
		case berry && strings.HasPrefix(line, "  resolution:"):
			res := unquote(strings.TrimPrefix(line, "  resolution:"))
			if i := strings.Index(res[min(1, len(res)):], "@npm:"); i >= 0 {
				n, v := splitSpec(res)
				out = append(out, Pkg{Eco: NPM, Name: n, Version: v})
			}
		case !berry && strings.HasPrefix(line, "  resolved "):
			resolved = unquote(strings.TrimPrefix(line, "  resolved "))
		case !berry && strings.HasPrefix(line, "  version "):
			v := unquote(strings.TrimPrefix(line, "  version "))
			if name != "" && registryTarball(resolved) {
				out = append(out, Pkg{Eco: NPM, Name: name, Version: v})
			}
		}
	}
	return out
}

// bunLock reads bun.lock: JSON with trailing commas. `packages` maps a key to ["name@1.2.3", registry, deps, integrity].
func bunLock(text string) []Pkg {
	var lock struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if json.Unmarshal([]byte(stripTrailingCommas(text)), &lock) != nil {
		return nil
	}
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Pkg
	for _, k := range keys {
		var spec string
		if len(lock.Packages[k]) == 0 || json.Unmarshal(lock.Packages[k][0], &spec) != nil {
			continue
		}
		name, version := splitSpec(spec)
		out = append(out, Pkg{Eco: NPM, Name: name, Version: version})
	}
	return out
}

// stripTrailingCommas drops a comma that closes an object or array, leaving strings alone.
func stripTrailingCommas(s string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
			b.WriteByte(c)
		case c == ',':
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\n' || s[j] == '\t' || s[j] == '\r') {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
