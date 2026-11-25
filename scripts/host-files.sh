#!/bin/sh
# Collect, from a Linux host, only the files `rasoat host --root` reads, as a tar on stdout. Usage: sh host-files.sh [ROOT] > host.tar
# ROOT is the tree to read (default /). Unpack the tar anywhere and run `rasoat host --root <dir>` on it.
#
# What it copies: os-release; the running kernel's release; the container markers (.dockerenv, run/.containerenv,
# proc/1/cgroup); the package database of the machine (dpkg status and status.d, apk installed, rpm db files); and for apt
# the origin data. An apt Release or InRelease is cut to its header (the Origin is there, the file hashes after it are
# not read). An apt Packages list is cut to the stanzas of the installed packages, "Package" and "Version" lines only:
# a list is tens of megabytes, and what rasoat asks of it is only which archive offers an installed name and version.
# Compressed lists (.lz4, .gz) are skipped, as rasoat does not read them.
#
# It needs POSIX sh, tar and awk, and runs no rasoat on the host and sends nothing anywhere. Root is not needed for the
# files a user can read. Nothing but the tar goes to stdout; errors go to stderr.
set -eu

ROOT=${1:-/}
case $ROOT in
/) base= ;;
*) base=${ROOT%/} ;;
esac
[ -d "${base:-/}" ] || { echo "host-files: $ROOT is not a directory" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' INT TERM HUP
STAGE=$WORK/root
PAIRS=$WORK/pairs
mkdir "$STAGE"
: > "$PAIRS"

# dest makes the directory for a staged file and names it.
dest() {
	mkdir -p "$STAGE/$(dirname "$1")"
	printf '%s' "$STAGE/$1"
}

# put copies a regular file (or what a link points to), keeping its path under the root.
put() {
	[ -f "$base/$1" ] || return 0
	out=$(dest "$1")
	cat "$base/$1" > "$out" 2>/dev/null || { rm -f "$out"; echo "host-files: cannot read $1" >&2; }
}

# mark records that a file exists, as an empty file.
mark() {
	[ -e "$base/$1" ] || return 0
	: > "$(dest "$1")"
}

put etc/os-release
put usr/lib/os-release
put proc/sys/kernel/osrelease
put proc/1/cgroup
mark .dockerenv
mark run/.containerenv
put lib/apk/db/installed
put usr/lib/apk/db/installed
for p in usr/lib/sysimage/rpm/rpmdb.sqlite var/lib/rpm/rpmdb.sqlite usr/lib/sysimage/rpm/Packages.db var/lib/rpm/Packages.db usr/lib/sysimage/rpm/Packages var/lib/rpm/Packages; do
	put "$p"
done

# dpkg: the status file cut to the four fields rasoat reads (a server's is megabytes whole, mostly descriptions), and the
# one-file-per-package directory, kept whole (small).
if [ -f "$base/var/lib/dpkg/status" ]; then
	out=$(dest var/lib/dpkg/status)
	awk '/^$/ || /^(Package|Version|Status|Source):/' "$base/var/lib/dpkg/status" > "$out" || { rm -f "$out"; echo "host-files: cannot read var/lib/dpkg/status" >&2; }
fi
for f in "$base"/var/lib/dpkg/status.d/*; do
	[ -f "$f" ] || continue
	name=${f##*/}
	case $name in *.md5sums) continue ;; esac
	put "var/lib/dpkg/status.d/$name"
done

# The installed "name version" pairs, parsed as rasoat parses them: a stanza counts when its Status ends in " installed".
set --
[ -f "$base/var/lib/dpkg/status" ] && set -- "$base/var/lib/dpkg/status"
for f in "$base"/var/lib/dpkg/status.d/*; do
	[ -f "$f" ] || continue
	case ${f##*/} in *.md5sums) continue ;; esac
	set -- "$@" "$f"
done
if [ $# -gt 0 ]; then
	awk '
	function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
	function flush() { if (name != "" && ver != "" && inst) print name " " ver; name = ""; ver = ""; inst = 0 }
	FNR == 1 { flush() }
	/^$/ { flush(); next }
	/^[ \t]/ { next }
	/^Package:/ { name = trim(substr($0, 9)); next }
	/^Version:/ { ver = trim(substr($0, 9)); next }
	/^Status:/ { s = trim(substr($0, 8)); inst = (length(s) >= 10 && substr(s, length(s) - 9) == " installed"); next }
	END { flush() }
	' "$@" > "$PAIRS"
fi

# apt: headers of the release files, and the installed stanzas of the Packages lists. File names are kept as they are.
for f in "$base"/var/lib/apt/lists/*; do
	[ -f "$f" ] || continue
	name=${f##*/}
	case $name in
	*_InRelease | *_Release)
		out=$(dest "var/lib/apt/lists/$name")
		awk '/^(MD5Sum|SHA256):/ { exit } { print }' "$f" > "$out" || { rm -f "$out"; echo "host-files: cannot read $name" >&2; }
		;;
	*_Packages)
		out=$(dest "var/lib/apt/lists/$name")
		PAIRS=$PAIRS awk '
		function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
		function flush() { if (name != "" && want[name " " ver]) { print pkg; print vline; print "" } name = ""; ver = ""; pkg = ""; vline = "" }
		BEGIN { pf = ENVIRON["PAIRS"]; while ((getline l < pf) > 0) want[l] = 1; close(pf) }
		/^$/ { flush(); next }
		/^Package: / { name = trim(substr($0, 10)); pkg = $0; next }
		/^Version: / { ver = trim(substr($0, 10)); vline = $0; next }
		END { flush() }
		' "$f" > "$out" || { rm -f "$out"; echo "host-files: cannot read $name" >&2; }
		;;
	esac
done

tar -cf - -C "$STAGE" .
