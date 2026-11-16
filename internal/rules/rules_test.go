package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAValidFileParsesIntoImageRulesAndDetectors(t *testing.T) {
	s, err := Parse([]byte(`{"version":1,"images":{"ghcr.io/x/y:1.0":"family:redis","a/b":"none"},"detectors":[
		{"name":"v","files":["VERSION","*.version"],"regex":"^(\\d+\\.\\d+\\.\\d+)$","product":"pkg:golang/golang.org/x/net"}]}`), "f")
	if err != nil {
		t.Fatal(err)
	}
	// an image is matched the way the files are read: without its registry and its tag
	if _, ok := s.Image("a/b"); !ok || len(s.Images) != 2 || s.Images[1].Image != "x/y" {
		t.Errorf("%+v", s.Images)
	}
	d := s.For("1.version")
	if len(d) != 1 || d[0].Product.String() != "pkg:golang/golang.org/x/net" {
		t.Fatalf("%+v", d)
	}
	if v, ok := d[0].Detect("# comment\r\n1.4.0\r\n"); !ok || v != "1.4.0" {
		t.Errorf("detect: %q %v", v, ok)
	}
	if len(s.For("version")) != 0 || len((*Set)(nil).For("VERSION")) != 0 {
		t.Error("a glob matches the whole name, and no rules match nothing")
	}
}

func TestEveryKindOfMistakeIsNamed(t *testing.T) {
	for in, want := range map[string]string{
		`{"images":{}}`:           `"version" must be 1`,
		`{"version":2}`:           `"version" must be 1`,
		`{"version":1,"extra":1}`: `unknown field "extra"`,
		`{"version":1,"detectors":[{"name":"a","files":["V"],"regex":"^(\\d)$","product":"none","x":1}]}`:                                                         `unknown field "x"`,
		`{"version":1,"images":{"a/b":"pkg:npm/x"}}`:                                                                                                              `images["a/b"]`,
		`{"version":1,"images":{"A B":"none"}}`:                                                                                                                   `not an image name`,
		`{"version":1,"detectors":[{"name":"a","files":[],"regex":"^(\\d)$","product":"none"}]}`:                                                                  `"files" needs at least one`,
		`{"version":1,"detectors":[{"name":"a","files":["sub/V"],"regex":"^(\\d)$","product":"none"}]}`:                                                           `no '/'`,
		`{"version":1,"detectors":[{"name":"a","files":["[V"],"regex":"^(\\d)$","product":"none"}]}`:                                                              `not a glob`,
		`{"version":1,"detectors":[{"name":"a","files":["V"],"regex":"^\\d$","product":"none"}]}`:                                                                 `exactly one capture group, it has 0`,
		`{"version":1,"detectors":[{"name":"a","files":["V"],"regex":"(","product":"none"}]}`:                                                                     `regex: `,
		`{"version":1,"detectors":[{"name":"a","files":["V"],"regex":"^(\\d)$","product":"pkg:pip/x"}]}`:                                                          `pkg:npm/<name>`,
		`{"version":1,"detectors":[{"name":"A","files":["V"],"regex":"^(\\d)$","product":"none"}]}`:                                                               `"name" is lower case`,
		`{"version":1,"detectors":[{"name":"a","files":["V"],"regex":"^(\\d)$","product":"none"},{"name":"a","files":["V"],"regex":"^(\\d)$","product":"none"}]}`: `used twice`,
		`{"version":1} {"version":1}`: `more than one JSON value`,
	} {
		_, err := Parse([]byte(in), "rules.json")
		if err == nil || !strings.Contains(err.Error(), want) || !strings.HasPrefix(err.Error(), "rules: rules.json: ") {
			t.Errorf("%s\n  got %v, want %q", in, err, want)
		}
	}
}

func TestALineThatIsNotAPlainVersionIsNotAVersion(t *testing.T) {
	s, _ := Parse([]byte(`{"version":1,"detectors":[{"name":"a","files":["V"],"regex":"^v=(.*)$","product":"none"}]}`), "f")
	d := s.Detectors[0]
	for _, in := range []string{"v=1.2.3; rm -rf /", "v=\x1b[31m1.2", "v=", "v=" + strings.Repeat("1", 80)} {
		if v, ok := d.Detect(in); ok {
			t.Errorf("%q gave %q", in, v)
		}
	}
	if v, ok := d.Detect("v=1.2.3-rc.1"); !ok || v != "1.2.3-rc.1" {
		t.Errorf("%q %v", v, ok)
	}
}

func TestTheDefaultFileIsOptionalAndANamedOneIsNot(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	if s, err := Load(""); s != nil || err != nil {
		t.Errorf("no file: %v %v", s, err)
	}
	if _, err := Load(filepath.Join(cfg, "nope.json")); err == nil {
		t.Error("a named file that is missing is an error")
	}
	if err := os.MkdirAll(filepath.Join(cfg, "rasoat"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "rasoat", "rules.json"), []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(""); s == nil || err != nil || s.Path != filepath.Join(cfg, "rasoat", "rules.json") {
		t.Errorf("%v %v", s, err)
	}
}
