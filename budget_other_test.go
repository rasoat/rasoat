//go:build !unix

package main

import "os/exec"

// maxRSS: no rusage here, so only the time is judged.
func maxRSS(*exec.Cmd) (int64, bool) { return 0, false }
