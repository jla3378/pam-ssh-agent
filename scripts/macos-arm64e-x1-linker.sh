#!/usr/bin/env bash
set -euo pipefail

args=()
for arg in "$@"; do
  case "$arg" in
    arm64e)
      args+=(arm64e.x1)
      ;;
    -arch=arm64e)
      args+=(-arch=arm64e.x1)
      ;;
    *arm64e-apple-macosx*)
      args+=("${arg/arm64e-apple/arm64e.x1-apple}")
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

exec xcrun clang "${args[@]}"
