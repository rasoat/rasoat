//go:build unix

package main

import (
	"os/exec"
	"runtime"
	"syscall"
)

// maxRSS is the peak resident set of a finished child, in bytes. ok false: the platform does not say.
func maxRSS(cmd *exec.Cmd) (bytes int64, ok bool) {
	ru, is := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !is {
		return 0, false
	}
	if runtime.GOOS == "darwin" {
		return int64(ru.Maxrss), true // bytes
	}
	return int64(ru.Maxrss) * 1024, true // kilobytes
}
