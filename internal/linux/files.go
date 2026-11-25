package linux

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// What each kind of file may weigh. A tree under examination can be hostile, so a file is refused by its size before any
// of it is read. The limits sit well above real inputs: the dpkg status of a large server is a few MB, an Ubuntu InRelease
// about 100 KB.
const (
	maxDpkgStatus  = 64 << 20  // var/lib/dpkg/status
	maxDpkgEntry   = 1 << 20   // one file of var/lib/dpkg/status.d
	maxApkDB       = 64 << 20  // lib/apk/db/installed
	maxRPMDB       = 256 << 20 // an rpm database, whatever its format
	maxSmallText   = 64 << 10  // os-release; also how much of a Release file is read for its header
	maxProcFile    = 4 << 10   // a file under /proc
	maxAptList     = 128 << 20 // one apt Packages list, which is streamed
	maxListEntries = 4096      // directory entries considered in apt lists and status.d
)

// tooManyFiles is the note for a directory cut at maxListEntries.
const tooManyFiles = "too-many-files"

var errNotRegular = errors.New("not a regular file")

// openFile opens a regular file under root. Under a mounted image every path, symlinks included, stays inside the image:
// a hostile image cannot make this read the machine it is examined on. Anything that is not a regular file (a FIFO, a
// device, a directory) is refused before open, so a FIFO cannot block it. On this machine's own "/" nothing can escape.
func openFile(root, rel string) (*os.File, error) {
	var f *os.File
	if root == "/" {
		p := filepath.Join(root, rel)
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, errors.New(rel + ": " + errNotRegular.Error())
		}
		if f, err = os.Open(p); err != nil {
			return nil, err
		}
	} else {
		r, err := os.OpenRoot(root)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		st, err := r.Stat(rel) // follows symlinks, inside the root only
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, errors.New(rel + ": " + errNotRegular.Error())
		}
		if f, err = r.Open(rel); err != nil {
			return nil, err
		}
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() { // swapped between the check and the open
		f.Close()
		return nil, errors.New(rel + ": " + errNotRegular.Error())
	}
	return f, nil
}

// existsIn: something is at rel, a symlink counted as itself and never followed.
func existsIn(root, rel string) bool {
	if root == "/" {
		_, err := os.Lstat(filepath.Join(root, rel))
		return err == nil
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return false
	}
	defer r.Close()
	_, err = r.Lstat(rel)
	return err == nil
}

// openCapped is openFile, refusing a file larger than max.
func openCapped(root, rel string, max int64) (*os.File, error) {
	f, err := openFile(root, rel)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || st.Size() > max {
		f.Close()
		return nil, errors.New(rel + ": too large")
	}
	return f, nil
}

// readFile reads a file under root, at most max bytes (see openFile).
func readFile(root, rel string, max int64) ([]byte, error) {
	f, err := openCapped(root, rel, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1)) // a file can grow after the size check
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New(rel + ": too large")
	}
	return b, nil
}

// listDir names the entries of a directory under root, the way readFile reads a file: inside the image. Sorted, and cut at
// maxListEntries: truncated says so.
func listDir(root, rel string) (names []string, truncated bool, err error) {
	var entries []fs.DirEntry
	if root == "/" {
		if entries, err = os.ReadDir("/" + rel); err != nil {
			return nil, false, err
		}
	} else {
		r, err := os.OpenRoot(root)
		if err != nil {
			return nil, false, err
		}
		defer r.Close()
		d, err := r.Open(rel)
		if err != nil {
			return nil, false, err
		}
		defer d.Close()
		if entries, err = d.ReadDir(-1); err != nil {
			return nil, false, err
		}
	}
	names = make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if len(names) > maxListEntries {
		names, truncated = names[:maxListEntries], true
	}
	return names, truncated, nil
}
