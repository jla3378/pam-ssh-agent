#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
toolchain=${PAM_ASAN_RUST_TOOLCHAIN:-nightly}
target_dir=${PAM_ASAN_TARGET_DIR:-$repo/target/asan}
asan_options=${PAM_ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}
rustc=$(rustup which --toolchain "$toolchain" rustc)

cd "$repo"
env \
  RUSTC="$rustc" \
  RUSTFLAGS='-Zsanitizer=address -Cforce-frame-pointers=yes' \
  ASAN_OPTIONS="$asan_options" \
  CARGO_TARGET_DIR="$target_dir" \
  rustup run "$toolchain" cargo test -Zbuild-std \
    --target aarch64-apple-darwin \
    --tests \
    --no-default-features \
    --locked \
    "$@"
env \
  RUSTC="$rustc" \
  RUSTFLAGS='-Zsanitizer=address -Cforce-frame-pointers=yes' \
  ASAN_OPTIONS="$asan_options" \
  CARGO_TARGET_DIR="$target_dir" \
  rustup run "$toolchain" cargo test -Zbuild-std \
    --target aarch64-apple-darwin \
    --manifest-path vendor/pam-bindings/Cargo.toml \
    --lib \
    "$@"
