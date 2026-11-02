package main

// `rasoat host` end to end: the program in a subprocess, a tree that looks as a machine does, data over real HTTP.
import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const hostIndex = `{"format":1,"built":"2099-01-01","files":{"debian-12":1},"lines":{"debian":[{"cycle":"12","eol":"2099-06-30"}],"linux":[]}}`

func hostData(built string) string {
	return `{"format":1,"id":"debian-12","built":"` + built + `","records":2}` + "\nopenssl\tDSA-1\t3.0.11-1\thigh\ncurl\tDSA-2\t8.0-1\tcritical\ncurl\t\t\t4\n"
}

func gz(text string) []byte {
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	z.Write([]byte(text))
	z.Close()
	return b.Bytes()
}

func machine(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
	write(t, root, "var/lib/dpkg/status", "Package: openssl\nStatus: install ok installed\nVersion: 3.0.2-1\n\nPackage: libcurl4\nStatus: install ok installed\nSource: curl\nVersion: 7.88-1\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n")
	return root
}

func dataServer(t *testing.T, requests *[]string, file []byte) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.URL.Path)
		switch r.URL.Path {
		case "/index.json":
			w.Write([]byte(hostIndex))
		case "/debian-12.tsv.gz":
			w.Write(file)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHostEndToEnd(t *testing.T) {
	var requests []string
	srv := dataServer(t, &requests, gz(hostData("2099-01-01")))
	cache := t.TempDir()
	env := map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL}
	root := machine(t)
	r := rasoat(t, cache, env, "", "host", "--root", root, "--json")
	var rep rep_
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("%v\n%s\n%s", err, r.stdout, r.stderr)
	}
	if r.code != 1 || rep.Target.Kind != "host" || rep.Host.Packages != 3 || rep.Host.OpenNoFix != 4 || rep.Summary.Vulnerable != 2 {
		t.Errorf("%d %+v", r.code, rep)
	}
	if rep.Results[0].Product != "pkg:curl" || rep.Results[0].Sources[0] != "libcurl4" || rep.Results[0].Advisories[0].URL != "https://osv.dev/vulnerability/DSA-2" {
		t.Errorf("worst first, by source package, naming the binary: %+v", rep.Results[0])
	}
	if !strings.Contains(rep.Host.UpgradeCmd, "libcurl4 openssl") {
		t.Error(rep.Host.UpgradeCmd)
	}
	// Only which release asks, and nothing about what it has.
	for _, path := range requests {
		if path != "/index.json" && path != "/debian-12.tsv.gz" {
			t.Error("asked for", path)
		}
	}
	// The next run within a day asks nothing.
	before := len(requests)
	if r := rasoat(t, cache, env, "", "host", "--root", root, "--json"); r.code != 1 || len(requests) != before {
		t.Error(r.code, len(requests)-before)
	}
	human := rasoat(t, cache, env, "", "host", "--root", root)
	for _, s := range []string{"VULNERABLE", "curl 7.88-1", "Debian GNU/Linux 12", "To upgrade what is listed", "Not checked: software installed outside", "Linux is a registered trademark"} {
		if !strings.Contains(human.stdout, s) {
			t.Error(s, human.stdout)
		}
	}
	if vi := rasoat(t, cache, map[string]string{"LANG": "vi_VN.UTF-8"}, "", "host", "--root", root); !strings.Contains(vi.stdout, "đã đọc 3 gói") {
		t.Error(vi.stdout)
	}
}

type rep_ struct {
	Target struct{ Kind string } `json:"target"`
	Host   struct {
		Packages   int    `json:"packages"`
		OpenNoFix  int    `json:"open_no_fix"`
		UpgradeCmd string `json:"upgrade_command"`
	} `json:"host"`
	Summary struct {
		Vulnerable int `json:"vulnerable"`
	} `json:"summary"`
	Data struct {
		Origin  string  `json:"origin"`
		Problem *string `json:"problem"`
	} `json:"data"`
	Notes   []string `json:"notes"`
	Results []struct {
		Product    string
		Sources    []string
		Advisories []struct{ URL string }
	} `json:"results"`
}

func TestHostDataIsJudgedBeforeItIsUsed(t *testing.T) {
	for name, file := range map[string][]byte{
		"not gzip":       []byte("<html>"),
		"another file":   gz(`{"format":1,"id":"ubuntu-22.04","built":"2099-01-01","records":1}` + "\nopenssl\tX\t9\thigh\n"),
		"unknown format": gz(`{"format":2,"id":"debian-12","built":"2099-01-01","records":1}` + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			var requests []string
			srv := dataServer(t, &requests, file)
			r := rasoat(t, t.TempDir(), map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL}, "", "host", "--root", machine(t), "--json")
			var rep rep_
			json.Unmarshal([]byte(r.stdout), &rep)
			if r.code != 3 || rep.Summary.Vulnerable != 0 || !strings.Contains(r.stdout, `"package-data-not-available"`) {
				t.Errorf("no data is no proof: exit %d %+v", r.code, rep)
			}
		})
	}
	t.Run("an older or smaller file loses to the cached one", func(t *testing.T) {
		cache := t.TempDir()
		write(t, cache, "rasoat/linux/index.json", hostIndex)
		write(t, cache, "rasoat/linux/debian-12.tsv", hostData("2099-01-01"))
		// Old mtime: due for a download.
		old := cacheOld(t, cache)
		var requests []string
		srv := dataServer(t, &requests, gz(`{"format":1,"id":"debian-12","built":"2020-01-01","records":2}`+"\n"))
		r := rasoat(t, cache, map[string]string{"RASOAT_LINUX_DATA_URL": srv.URL}, "", "host", "--root", machine(t), "--json")
		var rep rep_
		json.Unmarshal([]byte(r.stdout), &rep)
		if rep.Data.Origin != "cached" || rep.Data.Problem == nil || *rep.Data.Problem != "older" || rep.Summary.Vulnerable != 2 || !old {
			t.Errorf("%+v", rep.Data)
		}
	})
}

func TestHostWithoutARootOffLinuxIsAUsageError(t *testing.T) {
	r := rasoat(t, t.TempDir(), nil, "", "host", "--offline")
	if runtime.GOOS == "linux" {
		if r.code == 2 {
			t.Error(r.stderr)
		}
		return
	}
	if r.code != 2 || !strings.Contains(r.stderr, "not Linux") {
		t.Error(r.code, r.stderr)
	}
}

func TestANonLinuxRootIsAUsageError(t *testing.T) {
	if r := rasoat(t, t.TempDir(), nil, "", "host", "--root", t.TempDir(), "--offline"); r.code != 2 {
		t.Error(r.code)
	}
}

func TestHostToolTakesNoTarget(t *testing.T) {
	r := tool(t, "host", rep{"target": "/etc"})
	if r["isError"] != true {
		t.Error("the tool reads this machine only")
	}
	r = tool(t, "host", rep{"offline": true})
	if runtime.GOOS != "linux" && r["isError"] != true {
		t.Error(r)
	}
}

func cacheOld(t *testing.T, cache string) bool {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour)
	for _, f := range []string{"index.json", "debian-12.tsv"} {
		if err := os.Chtimes(filepath.Join(cache, "rasoat", "linux", f), old, old); err != nil {
			t.Fatal(err)
		}
	}
	return true
}
