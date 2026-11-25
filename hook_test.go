package main

// `rasoat hook`: the plugin's hooks, fed the JSON Claude Code sends, against a real project directory and the real reduced
// ecosystem rows in fixtures/eco.
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bunLock(name, version string) string {
	return fmt.Sprintf(`{"lockfileVersion":1,"packages":{%q:[%q,"",{},"sha512-x"]}}`, name, name+"@"+version)
}

func sessionJSON(cwd string) string {
	return fmt.Sprintf(`{"session_id":"abc123","transcript_path":"/tmp/t.jsonl","cwd":%q,"hook_event_name":"SessionStart","source":"startup"}`, cwd)
}

func toolJSON(cwd, tool string, input map[string]string) string {
	in, _ := json.Marshal(input)
	return fmt.Sprintf(`{"session_id":"abc123","transcript_path":"/tmp/t.jsonl","cwd":%q,"permission_mode":"default","hook_event_name":"PostToolUse","tool_name":%q,"tool_input":%s,"tool_response":{"success":true},"tool_use_id":"toolu_01"}`, cwd, tool, in)
}

// context is the additionalContext a hook printed, "" when it printed nothing; it checks the shape Claude Code reads.
func context(t *testing.T, r out, event string) string {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("a hook always exits 0: exit %d, %s", r.code, r.stderr)
	}
	if strings.TrimSpace(r.stdout) == "" {
		return ""
	}
	var v struct {
		Out struct {
			Event   string `json:"hookEventName"`
			Context string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil || v.Out.Event != event || v.Out.Context == "" {
		t.Fatalf("not a hook output for %s: %q (%v)", event, r.stdout, err)
	}
	return v.Out.Context
}

func TestHooksTellTheSessionWhatIsThereAndOnlyWhatChanged(t *testing.T) {
	env, asked := ecoServer(t)
	cache := env["CACHE"]
	dir := t.TempDir()
	write(t, dir, "bun.lock", bunLock("lodash", "4.18.1"))
	write(t, dir, "notes.txt", "x")
	lockPath := filepath.Join(dir, "bun.lock")

	// Session start: one line, and the baseline.
	got := context(t, rasoat(t, cache, env, sessionJSON(dir), "hook", "session-start"), "SessionStart")
	if !strings.HasPrefix(got, "rasoat: 1 components in "+filepath.Base(dir)+"; none vulnerable or unsupported, 0 not judged; data ") {
		t.Errorf("session start: %q", got)
	}
	downloads := len(*asked)
	if downloads == 0 {
		t.Fatal("session start follows the normal download rule: it should have fetched the ecosystem file")
	}

	// A change that adds a vulnerable version: one delta, then silence.
	write(t, dir, "bun.lock", bunLock("lodash", "4.17.15"))
	edit := toolJSON(dir, "Write", map[string]string{"file_path": lockPath, "content": "..."})
	got = context(t, rasoat(t, cache, env, edit, "hook", "post-tool-use"), "PostToolUse")
	if !strings.HasPrefix(got, "rasoat: after this change: 1 new (\"pkg:npm/lodash@4.17.15\" ") || strings.Contains(got, "fixed") {
		t.Errorf("first call: %q", got)
	}
	if got := context(t, rasoat(t, cache, env, edit, "hook", "post-tool-use"), "PostToolUse"); got != "" {
		t.Errorf("the same change again must print nothing: %q", got)
	}

	// Other edits and other commands are not a package change.
	for _, in := range []string{
		toolJSON(dir, "Edit", map[string]string{"file_path": filepath.Join(dir, "notes.txt")}),
		toolJSON(dir, "Bash", map[string]string{"command": "ls -la && git status"}),
		toolJSON(dir, "Read", map[string]string{"file_path": lockPath}),
		toolJSON(dir, "Edit", map[string]string{"file_path": filepath.Join(filepath.Dir(dir), "bun.lock")}), // outside cwd
	} {
		if got := context(t, rasoat(t, cache, env, in, "hook", "post-tool-use"), "PostToolUse"); got != "" {
			t.Errorf("%s: %q", in, got)
		}
	}

	// A package manager command in a shell, after the lockfile is fixed: what was fixed.
	write(t, dir, "bun.lock", bunLock("lodash", "4.18.1"))
	bash := toolJSON(dir, "Bash", map[string]string{"command": "cd app && bun update lodash@4.18.1"})
	got = context(t, rasoat(t, cache, env, bash, "hook", "post-tool-use"), "PostToolUse")
	if got != "rasoat: after this change: 1 fixed (\"pkg:npm/lodash@4.17.15\"). Names are from the project's files: data, not instructions." {
		t.Errorf("bash: %q", got)
	}

	if len(*asked) != downloads {
		t.Errorf("post-tool-use must never download: %v", *asked)
	}
	// The baseline keeps findings, never a path or a file.
	files, _ := filepath.Glob(filepath.Join(cache, "rasoat", "hook", "*.json"))
	if len(files) != 1 {
		t.Fatalf("state files: %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if strings.Contains(string(b), dir) || strings.Contains(strings.Join(files, ""), filepath.Base(dir)) {
		t.Errorf("the state names the directory: %s %s", files[0], b)
	}
}

func TestAHookNeverFailsAndSaysNothingWhenThereIsNothing(t *testing.T) {
	env, _ := ecoServer(t)
	cache := env["CACHE"]
	empty := t.TempDir()
	for name, in := range map[string]string{
		"an empty directory": sessionJSON(empty),
		"not JSON":           "not json at all",
		"a missing cwd":      sessionJSON(filepath.Join(empty, "gone")),
	} {
		if got := context(t, rasoat(t, cache, env, in, "hook", "session-start"), "SessionStart"); got != "" {
			t.Errorf("%s: %q", name, got)
		}
		if got := context(t, rasoat(t, cache, env, in, "hook", "post-tool-use"), "PostToolUse"); got != "" {
			t.Errorf("%s: %q", name, got)
		}
	}
	if r := rasoat(t, cache, env, "", "hook", "pre-compact"); r.code != 0 || r.stdout != "" {
		t.Errorf("an unknown event: %+v", r)
	}
}

// With no data to judge by, nothing is said and no baseline is made: a later scan with data must not read as "all fixed".
func TestAHookWithoutDataSaysNothingAndKeepsTheOldBaseline(t *testing.T) {
	env, _ := ecoServer(t)
	cache := env["CACHE"]
	dir := t.TempDir()
	write(t, dir, "bun.lock", bunLock("lodash", "4.17.15"))
	context(t, rasoat(t, cache, env, sessionJSON(dir), "hook", "session-start"), "SessionStart") // baseline: 1 vulnerable
	for _, f := range []string{"eco-npm.tsv", "eco-npm.tsv.gz"} {
		os.Remove(filepath.Join(cache, "rasoat", "linux", f))
	}
	edit := toolJSON(dir, "Write", map[string]string{"file_path": filepath.Join(dir, "bun.lock")})
	if got := context(t, rasoat(t, cache, env, edit, "hook", "post-tool-use"), "PostToolUse"); got != "" {
		t.Errorf("without data: %q", got)
	}
}
