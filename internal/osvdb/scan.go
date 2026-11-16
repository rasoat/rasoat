package osvdb

import (
	"sort"

	"github.com/rasoat/rasoat/internal/deps"
	"github.com/rasoat/rasoat/internal/linux"
)

// Vuln is one vulnerable (ecosystem, name, version), with every lockfile that resolves it.
type Vuln struct {
	Eco, Name, Version string
	Files              []string
	Verdict
}

// Outcome is the judgement of every package a scan read. Clean packages are counted, never listed: a monorepo has 1,500.
type Outcome struct {
	Vulns   []Vuln
	Checked map[string]int      // per ecosystem: distinct (name, version) judged
	NoData  map[string][]string // per ecosystem: the lockfiles that could not be judged for want of the data file
}

type key struct{ eco, name, version string }

// Scan judges the packages. An ecosystem whose file is not to be had (offline with no cache, or unreachable) lands in
// NoData and is never counted clean. The next package is left to the richer Next.js verdict.
func Scan(pkgs []deps.Pkg, offline bool, userAgent string) *Outcome {
	out := &Outcome{Checked: map[string]int{}, NoData: map[string][]string{}}
	files := map[key][]string{}
	names := map[string]map[string]bool{}
	for _, p := range pkgs {
		if p.Eco == deps.NPM && p.Name == "next" {
			continue
		}
		k := key{p.Eco, p.Name, p.Version}
		if !contains(files[k], p.File) {
			files[k] = append(files[k], p.File)
		}
		if names[p.Eco] == nil {
			names[p.Eco] = map[string]bool{}
		}
		names[p.Eco][p.Name] = true
	}
	ecos := make([]string, 0, len(names))
	for e := range names {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, eco := range ecos {
		lines, _ := linux.LoadFile(File[eco], offline, userAgent)
		if lines == nil {
			seen := map[string]bool{}
			for k, fs := range files {
				for _, f := range fs {
					if k.eco == eco && !seen[f] {
						seen[f] = true
						out.NoData[eco] = append(out.NoData[eco], f)
					}
				}
			}
			sort.Strings(out.NoData[eco])
			continue
		}
		ranges := Pick(lines, names[eco])
		for k, fs := range files {
			if k.eco != eco {
				continue
			}
			out.Checked[eco]++
			if v := Judge(k.version, ranges[k.name]); len(v.Hits) > 0 {
				sort.Strings(fs)
				out.Vulns = append(out.Vulns, Vuln{k.eco, k.name, k.version, fs, v})
			}
		}
	}
	sort.Slice(out.Vulns, func(i, j int) bool {
		a, b := out.Vulns[i], out.Vulns[j]
		if a.Eco != b.Eco {
			return a.Eco < b.Eco
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
