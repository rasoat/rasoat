//go:build unix

package linux

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO blocks until a writer comes: a hostile tree must not be able to stop a scan that way.
func TestFIFOStatusReturnsPromptly(t *testing.T) {
	root := hostileRoot(t)
	status := filepath.Join(root, "var/lib/dpkg/status")
	if err := syscall.Unlink(status); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(status, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Host, 1)
	go func() { done <- scanOffline(t, root) }()
	select {
	case h := <-done:
		if h.Packages != 0 {
			t.Errorf("%d packages", h.Packages)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}
