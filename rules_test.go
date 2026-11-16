package main

// The user's own rules, end to end: a real rules file in fixtures/rules, a project that names things no data judges.
import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rulesProject(t *testing.T) string {
	d := t.TempDir()
	write(t, d, "VERSION", "4.17.15\n")
	write(t, d, "cache.version", "redis=7.2.4\n")
	write(t, d, "BUILD", "build 9917\n")
	write(t, d, "docker-compose.yml", "services:\n  r:\n    image: bitnami/redis:7.2.4\n  l:\n    image: grafana/loki:3.1.0\n  m:\n    image: minio/minio:RELEASE.2024-01-01\n  p:\n    image: axllent/mailpit:3.1.0\n  z:\n    image: someone/else:1.0\n")
	return d
}

func TestRulesJudgeAcknowledgeAndListWhatTheyCannot(t *testing.T) {
	env, hits := noNetwork(t)
	cache := t.TempDir()
	r := rasoat(t, cache, env, "", "discover", rulesProject(t), "--json", "--rules", fixture("rules")+"/rules.json")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	v := parseJSON(t, r.stdout)
	judged := map[string]string{}
	for _, i := range items(v) {
		by := "<none>"
		if s, ok := i["judged_by"].(string); ok {
			by = s
		}
		if i["acknowledged"] == true {
			by = "acknowledged by " + i["rule"].(string)
		}
		judged[i["kind"].(string)+" "+i["product"].(string)+" "+str(i["version"])] = by
	}
	want := map[string]string{
		"package pkg:npm/lodash 4.17.15":       "rule:app-version → eco-npm",
		"pin redis 7.2.4":                      "rule:cache-version → lines",
		"image redis 7.2.4":                    "rule:image:bitnami/redis → lines",
		"pin build-stamp 9917":                 "acknowledged by build-stamp",
		"image minio/minio RELEASE.2024-01-01": "acknowledged by image:minio/minio",
		"image axllent/mailpit 3.1.0":          "acknowledged by image:axllent/mailpit",
		"image grafana/loki 3.1.0":             "<none>", // the rule names a family the index does not carry
		"image someone/else 1.0":               "<none>",
	}
	for k, w := range want {
		if got, ok := judged[k]; !ok || got != w {
			t.Errorf("%s: %q, want %q (all: %v)", k, got, w, judged)
		}
	}
	sum := v["summary"].(rep)
	if sum["acknowledged"] != 3.0 || sum["not_judged"] != 2.0 || sum["judged"] != 3.0 || sum["components"] != 8.0 {
		t.Errorf("summary %v", sum)
	}
	if notes := strings.Join(anyStrings(v["notes"]), " "); !strings.Contains(notes, "rule-family-unknown:loki-not-in-the-index") {
		t.Errorf("notes %q", notes)
	}
	if *hits != 0 {
		t.Errorf("discover made %d requests", *hits)
	}
}

func TestScanJudgesWhatADetectorFoundAndLeavesAcknowledgedOutOfNotJudged(t *testing.T) {
	env, _ := ecoServer(t)
	code, v := scanJSON(t, rulesProject(t), env, "--lang=en", "--rules", fixture("rules")+"/rules.json")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var lodash rep
	for _, r := range results(v) {
		if r["product"] == "pkg:npm/lodash" {
			lodash = r
		}
	}
	if lodash == nil || lodash["status"] != "vulnerable" || lodash["sources"].([]any)[0] != "VERSION" {
		t.Fatalf("lodash row: %v", lodash)
	}
	var left []string
	for _, i := range v["not_judged"].([]any) {
		left = append(left, i.(rep)["product"].(string))
	}
	if strings.Join(left, ",") != "grafana/loki,someone/else" {
		t.Errorf("not_judged %v: the acknowledged are known, so they are not listed", left)
	}
}

func TestRulesCheckSaysWhatEachRuleMatchesHere(t *testing.T) {
	env, hits := noNetwork(t)
	r := rasoat(t, t.TempDir(), env, "", "rules", "check", rulesProject(t), "--rules", fixture("rules")+"/rules.json")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"3 detectors, valid",
		"app-version -> pkg:npm/lodash",
		"package pkg:npm/lodash 4.17.15  VERSION  [rule:app-version → eco-npm]",
		"image:grafana/loki -> family:loki-not-in-the-index",
		"[not judged by any data]",
		"image:minio/minio -> none",
		"known, no data judges it",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
	empty := rasoat(t, t.TempDir(), env, "", "rules", "check", t.TempDir(), "--rules", fixture("rules")+"/rules.json")
	if !strings.Contains(empty.stdout, "no match here") {
		t.Errorf("an empty directory: %s", empty.stdout)
	}
	if *hits != 0 {
		t.Errorf("rules check made %d requests", *hits)
	}
}

func TestAMalformedRulesFileIsRefusedClearly(t *testing.T) {
	env, _ := noNetwork(t)
	for file, want := range map[string]string{
		"bad-regex-groups.json": `detectors["two"]: regex needs exactly one capture group, it has 2`,
		"bad-unknown-key.json":  `unknown field "files"`,
		"bad-product.json":      `detectors["x"]: product "pip:requests": say family:<id>, pkg:<eco>/<name> or none`,
		"missing.json":          "cannot read",
	} {
		path := filepath.Join(fixture("rules"), file)
		for _, args := range [][]string{{"rules", "check", "--rules", path}, {"discover", t.TempDir(), "--rules", path}} {
			r := rasoat(t, t.TempDir(), env, "", args...)
			if r.code != 2 || !strings.Contains(r.stderr, want) || !strings.Contains(r.stderr, "rules: ") {
				t.Errorf("%s %v: exit %d, %q", file, args[0], r.code, r.stderr)
			}
		}
	}
}

// A repository you scan must not change how it is judged: a rules.json inside it is just a file.
func TestAScannedDirectoryCannotSupplyRules(t *testing.T) {
	env, _ := noNetwork(t)
	d := t.TempDir()
	write(t, d, "VERSION", "4.17.15\n")
	b, _ := os.ReadFile(filepath.Join(fixture("rules"), "rules.json"))
	write(t, d, "rules.json", string(b))
	write(t, d, ".rasoat/rules.json", string(b))
	env["XDG_CONFIG_HOME"] = t.TempDir() // the user has no rules file
	r := rasoat(t, t.TempDir(), env, "", "discover", d, "--json")
	if r.code != 0 || len(items(parseJSON(t, r.stdout))) != 0 {
		t.Errorf("exit %d: %s", r.code, r.stdout)
	}
	// And the user's file is found at $XDG_CONFIG_HOME/rasoat/rules.json.
	cfg := t.TempDir()
	write(t, cfg, "rasoat/rules.json", string(b))
	env["XDG_CONFIG_HOME"] = cfg
	r = rasoat(t, t.TempDir(), env, "", "discover", d, "--json")
	if r.code != 0 || len(items(parseJSON(t, r.stdout))) == 0 {
		t.Errorf("the user's own rules were not read: %s", r.stdout)
	}
}
