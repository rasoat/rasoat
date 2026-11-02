package linux

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Package is one installed package. Advisories name the source package; a source package's version can differ from its
// binary's (gcc-12's libgcc, for one), so both are kept.
type Package struct {
	Name          string // binary package
	Version       string // [epoch:]version-release of the binary
	Source        string // source package
	SourceVersion string
	Stream        string // rpm module stream, from the modularity label: "8.1", "18"; empty when not modular
}

const maxDB = 512 << 20

// readFile reads a file under root, within the size limit. Under a mounted image every path, symlinks included, stays inside
// the image: a hostile image cannot make this read the machine it is examined on. On this machine's own "/" nothing can escape.
func readFile(root, rel string) ([]byte, error) {
	var f *os.File
	var err error
	if root == "/" {
		f, err = os.Open(filepath.Join(root, rel))
	} else {
		f, err = os.OpenInRoot(root, rel)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDB+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDB {
		return nil, errors.New(rel + ": too large")
	}
	return b, nil
}

// ReadPackages reads the package database of a family. os.ErrNotExist: this machine has none.
func ReadPackages(root, family string) ([]Package, error) {
	switch family {
	case "deb":
		return readDpkg(root)
	case "rpm":
		return readRPM(root)
	case "apk":
		return readApk(root)
	}
	return nil, os.ErrNotExist
}

func stanzaValue(line []byte, key string) (string, bool) {
	if bytes.HasPrefix(line, []byte(key)) {
		return string(bytes.TrimSpace(line[len(key):])), true
	}
	return "", false
}

func parseDpkg(data []byte, out []Package) []Package {
	var p Package
	installed := false
	flush := func() {
		if p.Name != "" && p.Version != "" && installed {
			if p.Source == "" {
				p.Source = p.Name
			}
			if p.SourceVersion == "" {
				p.SourceVersion = p.Version
			}
			out = append(out, p)
		}
		p, installed = Package{}, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if v, ok := stanzaValue(line, "Package:"); ok {
			p.Name = v
		} else if v, ok := stanzaValue(line, "Version:"); ok {
			p.Version = v
		} else if v, ok := stanzaValue(line, "Status:"); ok {
			installed = strings.HasSuffix(v, " installed") // "install ok installed", not "deinstall ok config-files"
		} else if v, ok := stanzaValue(line, "Source:"); ok {
			// "linux (6.1.106-3)": a source whose version is not the binary's.
			name, rest, has := strings.Cut(v, " ")
			p.Source = name
			if has {
				p.SourceVersion = strings.Trim(rest, "() ")
			}
		}
	}
	flush()
	return out
}

func readDpkg(root string) ([]Package, error) {
	var out []Package
	data, err := readFile(root, "var/lib/dpkg/status")
	if err == nil {
		out = parseDpkg(data, out)
	}
	// Distroless images keep one small status file per package here, with no Status line needing a package manager.
	if entries, e := os.ReadDir(filepath.Join(root, "var/lib/dpkg/status.d")); e == nil {
		for _, en := range entries {
			if strings.HasSuffix(en.Name(), ".md5sums") {
				continue
			}
			if b, e := readFile(root, "var/lib/dpkg/status.d/"+en.Name()); e == nil {
				out = parseDpkg(b, out)
			}
		}
		err = nil
	}
	return out, err
}

func readApk(root string) ([]Package, error) {
	var data []byte
	var err error
	for _, p := range []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"} {
		if data, err = readFile(root, p); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	var out []Package
	var p Package
	flush := func() {
		if p.Name != "" && p.Version != "" {
			if p.Source == "" {
				p.Source = p.Name
			}
			p.SourceVersion = p.Version
			out = append(out, p)
		}
		p = Package{}
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			flush()
		} else if len(line) > 2 && line[1] == ':' {
			switch line[0] {
			case 'P':
				p.Name = line[2:]
			case 'V':
				p.Version = line[2:]
			case 'o':
				p.Source = line[2:]
			}
		}
	}
	flush()
	return out, nil
}

// The rpm database has three file formats in use: SQLite (RHEL 9+, Fedora), Berkeley DB (RHEL 7 and 8, Amazon Linux 2) and
// NDB (SUSE). Each is a store of the same header blobs. Read here so no rpm program runs, and so a mounted image can be read
// from any OS. All offsets come from the file, so every read is bounds-checked: a broken file says nothing, it does not crash.

func readRPM(root string) ([]Package, error) {
	paths := []struct {
		rel  string
		read func([]byte) ([][]byte, error)
	}{
		{"usr/lib/sysimage/rpm/rpmdb.sqlite", readSQLite},
		{"var/lib/rpm/rpmdb.sqlite", readSQLite},
		{"usr/lib/sysimage/rpm/Packages.db", readNDB},
		{"var/lib/rpm/Packages.db", readNDB},
		{"usr/lib/sysimage/rpm/Packages", readBDB},
		{"var/lib/rpm/Packages", readBDB},
	}
	for _, p := range paths {
		data, err := readFile(root, p.rel)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		blobs, err := readSafely(p.read, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.rel, err)
		}
		var out []Package
		for _, b := range blobs {
			if pkg, ok := parseHeader(b); ok {
				out = append(out, pkg)
			}
		}
		return out, nil
	}
	return nil, os.ErrNotExist
}

// readSafely: the file is the judged machine's, perhaps a hostile image's. A reader's mistake on it is "unreadable", not a crash.
func readSafely(read func([]byte) ([][]byte, error), data []byte) (blobs [][]byte, err error) {
	defer func() {
		if recover() != nil {
			blobs, err = nil, errFormat
		}
	}()
	return read(data)
}

// parseHeader reads a header blob: index count, data length, 16-byte index entries, then data. All big-endian.
func parseHeader(b []byte) (Package, bool) {
	if len(b) < 8 {
		return Package{}, false
	}
	il, dl := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
	if il > 1<<20 || uint64(8+16*uint64(il)+uint64(dl)) > uint64(len(b)) {
		return Package{}, false
	}
	data := b[8+16*il:]
	data = data[:dl]
	var name, version, release, sourcerpm, stream string
	epoch := -1
	str := func(off uint32) string {
		if off >= uint32(len(data)) {
			return ""
		}
		if i := bytes.IndexByte(data[off:], 0); i >= 0 {
			return string(data[off : off+uint32(i)])
		}
		return ""
	}
	for i := range il {
		e := b[8+16*i:]
		tag, off := binary.BigEndian.Uint32(e), binary.BigEndian.Uint32(e[8:])
		switch tag {
		case 1000:
			name = str(off)
		case 1001:
			version = str(off)
		case 1002:
			release = str(off)
		case 1003:
			if uint64(off)+4 <= uint64(len(data)) {
				epoch = int(binary.BigEndian.Uint32(data[off:]))
			}
		case 1044:
			sourcerpm = str(off)
		case 5096:
			if parts := strings.Split(str(off), ":"); len(parts) >= 2 {
				stream = parts[1]
			}
		}
	}
	if name == "" || version == "" || name == "gpg-pubkey" {
		return Package{}, false
	}
	evr := version + "-" + release
	if epoch > 0 {
		evr = strconv.Itoa(epoch) + ":" + evr
	}
	p := Package{Name: name, Version: evr, Source: name, SourceVersion: evr, Stream: stream}
	// openssl-3.0.7-27.el9.src.rpm gives source openssl, 3.0.7-27.el9, with the binary's epoch.
	if s := strings.TrimSuffix(strings.TrimSuffix(sourcerpm, ".rpm"), ".src"); s != "" {
		rest, srcRelease := cutLast(s, '-')
		srcName, srcVersion := cutLast(rest, '-')
		if srcName != "" && srcVersion != "" {
			p.Source = srcName
			p.SourceVersion = srcVersion + "-" + srcRelease
			if epoch > 0 {
				p.SourceVersion = strconv.Itoa(epoch) + ":" + p.SourceVersion
			}
		}
	}
	return p, true
}

var errFormat = errors.New("not a database this program can read")

func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

type sqliteDB struct {
	data     []byte
	pageSize int
	usable   int
	seen     map[uint32]bool // a hostile file can point a page at itself: each is walked once
}

func (d *sqliteDB) page(n uint32) []byte {
	start := (int64(n) - 1) * int64(d.pageSize)
	if n == 0 || start+int64(d.pageSize) > int64(len(d.data)) {
		return nil
	}
	return d.data[start : start+int64(d.pageSize)]
}

// cellPayload returns a leaf cell's record, following its overflow chain.
func (d *sqliteDB) cellPayload(cell []byte) []byte {
	size, n := varint(cell)
	if n == 0 || size > maxDB {
		return nil
	}
	_, m := varint(cell[n:])
	if m == 0 {
		return nil
	}
	body := cell[n+m:]
	u := d.usable
	x := u - 35
	local := int(size)
	if int(size) > x {
		minLocal := (u-12)*32/255 - 23
		k := minLocal + (int(size)-minLocal)%(u-4)
		local = minLocal
		if k <= x {
			local = k
		}
	}
	if local > len(body) {
		return nil
	}
	out := make([]byte, 0, size)
	out = append(out, body[:local]...)
	if local == int(size) {
		return out
	}
	if local+4 > len(body) {
		return nil
	}
	next := binary.BigEndian.Uint32(body[local:])
	for next != 0 && len(out) < int(size) {
		p := d.page(next)
		if p == nil || u > len(p) {
			return nil
		}
		next = binary.BigEndian.Uint32(p)
		take := min(u-4, int(size)-len(out))
		out = append(out, p[4:4+take]...)
	}
	return out
}

func (d *sqliteDB) walkTable(n uint32, depth int, visit func(record []byte)) {
	p := d.page(n)
	if p == nil || depth > 32 || d.seen[n] {
		return
	}
	d.seen[n] = true
	offset := 0
	if n == 1 {
		offset = 100
	}
	if offset+8 > len(p) {
		return
	}
	kind := p[offset]
	cells := int(binary.BigEndian.Uint16(p[offset+3:]))
	head := offset + 8
	if kind == 0x05 {
		head = offset + 12
	} else if kind != 0x0d {
		return
	}
	for i := range cells {
		if head+2*i+2 > len(p) {
			return
		}
		at := int(binary.BigEndian.Uint16(p[head+2*i:]))
		if at >= len(p) {
			continue
		}
		if kind == 0x05 {
			if at+4 <= len(p) {
				d.walkTable(binary.BigEndian.Uint32(p[at:]), depth+1, visit)
			}
			continue
		}
		visit(d.cellPayload(p[at:]))
	}
	if kind == 0x05 && offset+12 <= len(p) {
		d.walkTable(binary.BigEndian.Uint32(p[offset+8:]), depth+1, visit)
	}
}

// recordColumns decodes a record's columns as bytes; integers come back as big-endian bytes, NULL as nil.
func recordColumns(rec []byte) [][]byte {
	headerSize, n := varint(rec)
	if n == 0 || headerSize > uint64(len(rec)) || headerSize < uint64(n) {
		return nil
	}
	var cols [][]byte
	body := rec[headerSize:]
	for h := rec[n:headerSize]; len(h) > 0; {
		t, m := varint(h)
		if m == 0 {
			return nil
		}
		h = h[m:]
		size := uint64(0)
		switch {
		case t >= 12 && t%2 == 0:
			size = (t - 12) / 2
		case t >= 13:
			size = (t - 13) / 2
		case t >= 1 && t <= 4:
			size = t
		case t == 5:
			size = 6
		case t == 6 || t == 7:
			size = 8
		}
		if size > uint64(len(body)) {
			return nil
		}
		cols = append(cols, body[:size])
		body = body[size:]
	}
	return cols
}

func readSQLite(data []byte) ([][]byte, error) {
	if len(data) < 100 || !bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		return nil, errFormat
	}
	size := int(binary.BigEndian.Uint16(data[16:]))
	if size == 1 {
		size = 65536
	}
	if size < 512 {
		return nil, errFormat
	}
	d := &sqliteDB{data: data, pageSize: size, usable: size - int(data[20]), seen: map[uint32]bool{}}
	if d.usable < 480 {
		return nil, errFormat
	}
	var root uint32
	d.walkTable(1, 0, func(rec []byte) { // sqlite_schema: type, name, tbl_name, rootpage, sql
		c := recordColumns(rec)
		if len(c) >= 4 && string(c[0]) == "table" && string(c[1]) == "Packages" {
			for _, b := range c[3] {
				root = root<<8 | uint32(b)
			}
		}
	})
	if root == 0 {
		return nil, errFormat
	}
	d.seen = map[uint32]bool{}
	var out [][]byte
	d.walkTable(root, 0, func(rec []byte) {
		c := recordColumns(rec)
		if len(c) >= 2 && len(c[1]) > 0 {
			out = append(out, c[1])
		}
	})
	return out, nil
}

// readBDB reads a Berkeley DB hash file: a meta page, then pages of key/value pairs. A value is stored on overflow pages,
// or inline when small. Byte order is the writer's, told by the magic number.
func readBDB(data []byte) ([][]byte, error) {
	if len(data) < 72 {
		return nil, errFormat
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if bo.Uint32(data[12:]) != 0x061561 {
		bo = binary.BigEndian
		if bo.Uint32(data[12:]) != 0x061561 {
			return nil, errFormat
		}
	}
	pageSize := bo.Uint32(data[20:])
	if pageSize < 512 || pageSize > 65536 {
		return nil, errFormat
	}
	last := bo.Uint32(data[32:])
	page := func(n uint32) []byte {
		start := uint64(n) * uint64(pageSize)
		if start+uint64(pageSize) > uint64(len(data)) {
			return nil
		}
		return data[start : start+uint64(pageSize)]
	}
	var out [][]byte
	for n := uint32(1); n <= last; n++ {
		p := page(n)
		if p == nil {
			break
		}
		if p[25] != 2 && p[25] != 13 { // hash pages, unsorted and sorted
			continue
		}
		entries := int(bo.Uint16(p[20:]))
		for i := 1; i < entries; i += 2 { // key, value, key, value
			if 26+2*i+2 > len(p) {
				break
			}
			at := int(bo.Uint16(p[26+2*i:]))
			if at >= len(p) {
				continue
			}
			switch p[at] {
			case 3: // off-page: 3 bytes padding, first page, total length
				if at+12 > len(p) {
					continue
				}
				pgno, total := bo.Uint32(p[at+4:]), bo.Uint32(p[at+8:])
				if total > maxDB {
					continue
				}
				blob := make([]byte, 0, min(total, uint32(len(data))))
				for pgno != 0 && uint32(len(blob)) < total {
					o := page(pgno)
					if o == nil || o[25] != 7 {
						break
					}
					use := int(bo.Uint16(o[22:]))
					if use == 0 || 26+use > len(o) {
						break
					}
					blob = append(blob, o[26:26+use]...)
					pgno = bo.Uint32(o[16:])
				}
				if uint32(len(blob)) == total {
					out = append(out, blob)
				}
			case 1: // inline, up to the previous entry's start
				end := len(p)
				if i >= 2 {
					end = int(bo.Uint16(p[26+2*(i-1):]))
				}
				if at+1 <= end && end <= len(p) {
					out = append(out, p[at+1:end])
				}
			}
		}
	}
	return out, nil
}

// readNDB reads rpm's own format: a slot table of (magic, package, block offset, block count), then blobs in 16-byte blocks.
func readNDB(data []byte) ([][]byte, error) {
	le := binary.LittleEndian
	if len(data) < 32 || string(data[:4]) != "RpmP" {
		return nil, errFormat
	}
	slotPages := le.Uint32(data[12:])
	if slotPages == 0 || uint64(slotPages)*4096 > uint64(len(data)) {
		return nil, errFormat
	}
	var out [][]byte
	end := int(slotPages) * 4096
	for at := 32; at+16 <= end; at += 16 {
		s := data[at:]
		if string(s[:4]) != "Slot" {
			continue
		}
		index, block := le.Uint32(s[4:]), uint64(le.Uint32(s[8:]))
		if index == 0 || block*16+16 > uint64(len(data)) {
			continue
		}
		b := data[block*16:]
		if string(b[:4]) != "BlbS" || le.Uint32(b[4:]) != index {
			continue
		}
		size := uint64(le.Uint32(b[12:]))
		if 16+size > uint64(len(b)) {
			continue
		}
		out = append(out, b[16:16+size])
	}
	return out, nil
}
