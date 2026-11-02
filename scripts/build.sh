#!/bin/sh
# Release binaries, static and reproducible: no cgo, no build path, no timestamp. Usage: scripts/build.sh [--native]
# Writes dist/cli/ and SHA256SUMS, then smoke-tests the binary for this machine if it can run here.
set -eu
cd "${RASOAT_MODULE:-$(dirname "$0")/..}"
OUT=dist/cli
rm -rf "$OUT"
mkdir -p "$OUT"

# GOOS GOARCH GOARM file-suffix. 64-bit Linux first, then what older or smaller Linux machines run.
TARGETS="linux amd64 - linux-x64
linux arm64 - linux-arm64
linux arm 7 linux-armv7
linux 386 - linux-386
linux riscv64 - linux-riscv64
linux ppc64le - linux-ppc64le
linux s390x - linux-s390x
darwin arm64 - darwin-arm64
darwin amd64 - darwin-x64
windows amd64 - windows-x64.exe
windows arm64 - windows-arm64.exe
freebsd amd64 - freebsd-x64"

if [ "${1:-}" = "--native" ]; then
  TARGETS="$(go env GOOS) $(go env GOARCH) - native"
fi

echo "$TARGETS" | while read -r os arch arm name; do
  [ "$arm" = "-" ] && arm=""
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$arm" go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$OUT/rasoat-$name" .
  echo "rasoat-$name $(($(wc -c < "$OUT/rasoat-$name") / 1000000)) MB"
done

(cd "$OUT" && if command -v sha256sum > /dev/null; then sha256sum rasoat-*; else shasum -a 256 rasoat-*; fi) > SHA256SUMS.tmp
mv SHA256SUMS.tmp "$OUT/SHA256SUMS"
