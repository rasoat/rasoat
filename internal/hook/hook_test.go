package hook

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rasoat/rasoat/internal/project"
)

// A scan that downloads past the budget does not hold the session: the cache answers, and the line says so.
func TestSessionStartFallsBackToTheCacheWhenTheDownloadIsSlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("RASOAT_DATA_URL", srv.URL+"/snapshot")
	t.Setenv("RASOAT_LINUX_DATA_URL", srv.URL)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ScanBudget = 200 * time.Millisecond
	t.Cleanup(func() { ScanBudget = 15 * time.Second })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bun.lock"), []byte(`{"packages":{"lodash":["lodash@4.17.15","",{},"x"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got := sessionStart(dir, nil)
	if time.Since(start) > 2500*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
	if !strings.Contains(got, "The download was slow, so this used the data already here.") || !strings.HasPrefix(got, "rasoat: 1 components in ") {
		t.Errorf("%q", got)
	}
}

func TestACommandIsAPackageChangeOnlyWhenItChangesWhatIsResolved(t *testing.T) {
	for cmd, want := range map[string]bool{
		"npm install":                     true,
		"npm i left-pad":                  true,
		"pnpm add -D vitest":              true,
		"yarn":                            true,
		"yarn add x@1":                    true,
		"bun update lodash@4.18.1":        true,
		"cd web && bun install --frozen":  true,
		"cargo add serde":                 true,
		"cargo update -p tokio":           true,
		"go get golang.org/x/net@v0.60.0": true,
		"go mod tidy":                     true,
		"docker compose pull":             true,
		"docker-compose pull web":         true,
		"npm run build":                   false,
		"npm test":                        false,
		"cargo build":                     false,
		"go build ./...":                  false,
		"ls bun-install-notes":            false,
		"git commit -m 'npm install'":     false,
		"echo hi":                         false,
	} {
		if got := packageChange.MatchString(cmd); got != want {
			t.Errorf("%q: %v, want %v", cmd, got, want)
		}
	}
}

func TestOnlyWhatTheWalkReadsIsAManifestAndItsRootIsTheProject(t *testing.T) {
	for p, root := range map[string]string{
		"/p/bun.lock":                 "/p",
		"/p/apps/web/package.json":    "/p/apps/web",
		"/p/Cargo.lock":               "/p",
		"/p/go.sum":                   "/p",
		"/p/docker-compose.yml":       "/p",
		"/p/Dockerfile.prod":          "/p",
		"/p/.nvmrc":                   "/p",
		"/p/.github/workflows/ci.yml": "/p",
		"/p/wp-includes/version.php":  "/p",
	} {
		if !project.IsManifest(p) {
			t.Errorf("%s should be a manifest", p)
		}
		if got := filepath.ToSlash(project.RootOf(p)); got != root { // native separators on Windows
			t.Errorf("%s: root %s, want %s", p, got, root)
		}
	}
	for _, p := range []string{"/p/README.md", "/p/src/main.go", "/p/ci.yml", "/p/version.php", "/p/other/workflows/ci.yml"} {
		if project.IsManifest(p) {
			t.Errorf("%s is not a manifest", p)
		}
	}
}
