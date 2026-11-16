package main

import (
	"encoding/json"
	"testing"
)

func parseJSON(t *testing.T, text string) rep {
	t.Helper()
	var v rep
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatal(err, text)
	}
	return v
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
