#!/usr/bin/env bash
# portability_test.sh -- end-to-end portability gate for linpersist.
#
# Builds the agent for every target architecture with CGO disabled,
# then runs tools/verify_static.sh against each output binary. Reports
# size and `file` summary per arch. Exits non-zero if any build or
# any static-link check fails.
#
# Run from the repository root:
#   ./tools/portability_test.sh
#
# Requires: Go 1.22+, bash, file, readelf, ldd (any of glibc / musl).

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v go >/dev/null 2>&1; then
  echo "portability_test: go not found in PATH" >&2
  exit 2
fi

go_ver=$(go version)
echo "Toolchain: $go_ver"
echo

mkdir -p dist

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "linux/386"
  "linux/arm/7"
)

# Build flags. -tags uses the comma form (osusergo,netgo) rather than
# the space-quoted form so that bash word-splitting after $GOFLAGS
# expansion does not break the quoting. The Makefile mirrors this.
GOFLAGS="-trimpath -buildvcs=false -tags=osusergo,netgo"
LDFLAGS="-s -w -X main.version=portability-test -X main.commit=local"

fail=0

for t in "${TARGETS[@]}"; do
  os=${t%%/*}
  rest=${t#*/}
  arch=${rest%%/*}
  goarm=""
  case "$rest" in
    */*) goarm="${rest##*/}";;
  esac

  suffix=""
  [ -n "$goarm" ] && suffix="v$goarm"
  out="dist/linpersist-$os-$arch$suffix"

  echo "==> Building $out"
  env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$goarm" \
    go build $GOFLAGS -ldflags="$LDFLAGS" -o "$out" ./cmd/linpersist
  size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out")
  echo "    size: $size bytes"

  # verify_static.sh validates ELF + statically linked + no PT_INTERP
  # and prints its own `file:` / `ldd:` summary, so we do not duplicate
  # those lines here. ldd only works on the native arch; the script
  # handles that gracefully on cross-arch binaries.
  if ! ./tools/verify_static.sh "$out"; then
    echo "FAIL: $out failed static-link gate" >&2
    fail=1
  fi
  echo
done

if [ $fail -ne 0 ]; then
  echo "Portability gate: FAIL" >&2
  exit 1
fi

echo "Portability gate: OK"
echo
echo "Smoke-test native binary (--version, --help, empty run):"
native_arch=$(go env GOARCH)
native="dist/linpersist-linux-${native_arch}"
if [ -x "$native" ]; then
  "$native" --version
  echo "----"
  "$native" --help 2>&1 | head -12 || true
  echo "----"
  "$native" --log-level=error </dev/null | head -3 || true
fi
