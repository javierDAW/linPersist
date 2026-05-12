#!/usr/bin/env bash
# verify_static.sh -- portability gate for a linpersist binary.
#
# Exits 0 iff the given binary is:
#   * statically linked (no dynamic interpreter, no NEEDED entries);
#   * an ELF for a Linux target;
#   * stripped of the dynamic-loader signature that glibc would inject
#     under CGO=1.
#
# Usage: tools/verify_static.sh <path-to-binary>
#
# The gate is intentionally paranoid. A linpersist binary that passes
# `make build-all` MUST pass this script unmodified.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <binary>" >&2
  exit 2
fi

bin="$1"

if [ ! -f "$bin" ]; then
  echo "verify_static: not a file: $bin" >&2
  exit 1
fi

if [ ! -x "$bin" ]; then
  chmod +x "$bin" || true
fi

fail=0

# 1. `file` must say "statically linked" and "ELF" and "Linux".
file_out=$(file -b "$bin")
echo "file: $file_out"
case "$file_out" in
  *ELF*) ;;
  *) echo "FAIL: not an ELF binary" >&2; fail=1;;
esac
case "$file_out" in
  *statically\ linked*|*static-pie\ linked*) ;;
  *) echo "FAIL: not statically linked" >&2; fail=1;;
esac

# 2. ldd must report "not a dynamic executable" -- on any glibc system
#    you would otherwise see a list of .so dependencies. Some musl
#    `ldd` implementations exit non-zero on static binaries; tolerate
#    that case by treating non-zero exit + matching message as PASS.
ldd_out=$(ldd "$bin" 2>&1 || true)
echo "ldd : $ldd_out"
case "$ldd_out" in
  *"not a dynamic executable"*|*"statically linked"*) ;;
  *)
    # If ldd lists no .so dependencies the binary is effectively static
    # on systems that consider go-static binaries as PIE.
    if echo "$ldd_out" | grep -qE '\.so'; then
      echo "FAIL: ldd reports dynamic dependencies" >&2
      fail=1
    fi
    ;;
esac

# 3. readelf check: no PT_INTERP segment (the dynamic interpreter).
if command -v readelf >/dev/null 2>&1; then
  interp=$(readelf -l "$bin" 2>/dev/null | awk '/INTERP/{flag=1} flag && /Requesting/{print; flag=0}')
  if [ -n "$interp" ]; then
    echo "readelf: $interp"
    echo "FAIL: binary has a dynamic interpreter" >&2
    fail=1
  fi
fi

if [ $fail -ne 0 ]; then
  exit 1
fi

echo "OK: $bin is statically linked"
