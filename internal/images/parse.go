package images

import (
	"strings"

	"github.com/rasoat/rasoat/internal/core"
)

var (
	composeName = core.NewRe(`(?i)^(docker-)?compose([.-][\w.-]+)?\.ya?ml$`)
	varRe       = core.NewRe(`\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)`)
	argRe       = core.NewRe(`(?i)^ARG\s+(\w+)(?:=(.*))?$`)
	fromRe      = core.NewRe(`(?i)^FROM\s+(.*)$`)
	imageRe     = core.NewRe(`^\s*-?\s*image:\s*(.+)$`)
	ciRe        = core.NewRe(`(?:^|[\s{,])(node|bun|go|python|php)-version:[ \t]*(.*)$`)
	listItem    = core.NewRe(`^\s*-\s*(.+)$`)
)

// IsDockerfile: Dockerfile, Dockerfile.prod, api.Dockerfile, Containerfile.
func IsDockerfile(name string) bool {
	n := strings.ToLower(name)
	return n == "dockerfile" || n == "containerfile" || strings.HasPrefix(n, "dockerfile.") || strings.HasSuffix(n, ".dockerfile")
}

// IsCompose: docker-compose.yml, compose.yaml, docker-compose.prod.yml.
func IsCompose(name string) bool { return composeName.MatchString(name) }

// IsWorkflow: a file directly in .github/workflows, given its directory's name and its own.
func IsWorkflow(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return s
}

// expand fills `$X`, `${X}` and `${X:-default}` from args, or from the default. What has neither stays as written.
func expand(s string, args map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		g := varRe.FindStringSubmatch(m)
		name, def, hasDef := g[1], g[2], strings.Contains(m, "-")
		if name == "" {
			name = g[3]
		}
		if v, ok := args[name]; ok && v != "" {
			return v
		}
		if hasDef {
			return def
		}
		return m
	})
}

// Dockerfile reads each FROM: not a build stage's name, not `scratch`. An `ARG NAME=default` before the first FROM fills
// `${NAME}` when its default is literal.
func Dockerfile(text string) []Ref {
	var out []Ref
	args, stages, seenFrom := map[string]string{}, map[string]bool{}, false
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\\\n", " ")
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if m := argRe.FindStringSubmatch(l); m != nil && !seenFrom {
			args[m[1]] = unquote(m[2])
			continue
		}
		m := fromRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		seenFrom = true
		var image, stage string
		f := strings.Fields(m[1])
		for i := 0; i < len(f); i++ {
			if strings.HasPrefix(f[i], "--") {
				continue
			}
			image = f[i]
			if i+2 < len(f) && strings.EqualFold(f[i+1], "as") {
				stage = strings.ToLower(f[i+2])
			}
			break
		}
		skip := image == "" || strings.EqualFold(image, "scratch") || stages[strings.ToLower(image)]
		if stage != "" {
			stages[stage] = true
		}
		if !skip {
			out = append(out, ParseRef(expand(image, args)))
		}
	}
	return out
}

// Compose reads each `image:` line, as plain text: no YAML library, so an anchor or a merge key is not followed.
func Compose(text string) []Ref {
	var out []Ref
	for _, l := range strings.Split(text, "\n") {
		if m := imageRe.FindStringSubmatch(strings.TrimRight(l, "\r")); m != nil {
			if v := unquote(m[1]); v != "" {
				out = append(out, ParseRef(expand(v, nil)))
			}
		}
	}
	return out
}

// Workflow reads the runtime pins of a GitHub workflow: a scalar, an inline list, or a block list.
func Workflow(text string) []Ref {
	var out []Ref
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, l := range lines {
		m := ciRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		var values []string
		indent := len(l) - len(strings.TrimLeft(l, " "))
		switch v := unquote(m[2]); {
		case strings.HasPrefix(v, "["):
			list, _, _ := strings.Cut(strings.TrimPrefix(v, "["), "]")
			for _, x := range strings.Split(list, ",") {
				values = append(values, unquote(x))
			}
		case v != "":
			// A scalar, or one key of a flow map: `with: { bun-version: 1.4.4 }`.
			if !strings.Contains(v, "${{") {
				v, _, _ = strings.Cut(v, ",")
				v, _, _ = strings.Cut(v, "}")
			}
			values = []string{unquote(v)}
		default:
			for _, next := range lines[i+1:] {
				li := listItem.FindStringSubmatch(next)
				if li == nil || len(next)-len(strings.TrimLeft(next, " ")) < indent {
					break
				}
				values = append(values, unquote(li[1]))
			}
		}
		for _, v := range values {
			if v != "" {
				out = append(out, FromPin(m[1], v))
			}
		}
	}
	return out
}
