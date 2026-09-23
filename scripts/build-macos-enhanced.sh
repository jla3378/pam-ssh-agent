#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/build-macos-enhanced.sh [--plan]

Xcode-compatible switches:
  ENABLE_ENHANCED_SECURITY=YES|NO
  ENABLE_POINTER_AUTHENTICATION=YES|NO
  ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE=YES|NO

Optional configuration:
  MACOS_ENHANCED_RUST_TOOLCHAIN=<rustup toolchain>
  MACOS_ENHANCED_TARGET_DIR=<build directory>
  MACOS_ENHANCED_OUTPUT=<output dylib>
  MACOS_ENHANCED_EXTRA_RUSTFLAGS=<additional rustc flags>
  CODE_SIGN_IDENTITY=<codesign identity>
EOF
}

case "${1:-}" in
  "") ;;
  --plan) plan_only=1 ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

require_switch() {
  local name=$1
  local value=$2
  case "$value" in
    YES|NO) ;;
    *)
      printf '%s must be YES or NO, got %s\n' "$name" "$value" >&2
      exit 2
      ;;
  esac
}

enhanced=${ENABLE_ENHANCED_SECURITY:-NO}
pointer_auth=${ENABLE_POINTER_AUTHENTICATION:-$enhanced}
checked_pointer=${ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE:-NO}
require_switch ENABLE_ENHANCED_SECURITY "$enhanced"
require_switch ENABLE_POINTER_AUTHENTICATION "$pointer_auth"
require_switch ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE "$checked_pointer"

architectures=(arm64)
[[ "$pointer_auth" == YES ]] && architectures+=(arm64e)
[[ "$checked_pointer" == YES ]] && architectures+=(arm64e.x1)

printf 'ENABLE_ENHANCED_SECURITY=%s\n' "$enhanced"
printf 'ENABLE_POINTER_AUTHENTICATION=%s\n' "$pointer_auth"
printf 'ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE=%s\n' "$checked_pointer"
printf 'ARCHS=%s\n' "${architectures[*]}"

if [[ ${plan_only:-0} == 1 ]]; then
  exit 0
fi

[[ $(uname -s) == Darwin ]] || {
  printf '%s\n' 'macOS is required' >&2
  exit 1
}

for command in codesign rustup xcrun; do
  command -v "$command" >/dev/null || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 1
  }
done

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
toolchain=${MACOS_ENHANCED_RUST_TOOLCHAIN:-nightly}
target_root=${MACOS_ENHANCED_TARGET_DIR:-$repo/target/macos-enhanced}
output=${MACOS_ENHANCED_OUTPUT:-$target_root/release/libpam_ssh_agent.dylib}
linker="$repo/scripts/macos-arm64e-x1-linker.sh"
cargo=$(rustup which cargo --toolchain "$toolchain")
rustc=$(rustup which rustc --toolchain "$toolchain")
toolchain_bin=$(dirname -- "$cargo")
export PATH="$toolchain_bin:$PATH"
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER

if [[ -n ${CARGO_ENCODED_RUSTFLAGS:-} ]]; then
  printf '%s\n' 'CARGO_ENCODED_RUSTFLAGS is incompatible with verified hardening flags' >&2
  exit 2
fi

"$rustc" -Vv
rust_components=$(rustup component list --toolchain "$toolchain" --installed)
grep -Eq '^rust-src($|-)' <<<"$rust_components" || {
  printf 'rust-src is required for %s\n' "$toolchain" >&2
  exit 1
}

printf 'DEVELOPER_DIR=%s\n' "$(xcode-select -p)"
xcrun xcodebuild -version
printf 'MACOSX_SDK_VERSION=%s\n' "$(xcrun --sdk macosx --show-sdk-version)"
printf 'MACOSX_SDK_PATH=%s\n' "$(xcrun --sdk macosx --show-sdk-path)"

base_rustflags=${MACOS_ENHANCED_EXTRA_RUSTFLAGS:-}
case "$base_rustflags" in
  *panic=abort*)
    printf '%s\n' 'panic=abort is incompatible with PAM panic containment' >&2
    exit 2
    ;;
esac
if [[ "$enhanced" == YES ]]; then
  base_rustflags="${base_rustflags:+$base_rustflags }-Zstack-protector=strong -Coverflow-checks=yes"
fi

artifacts=()
arm64_dir="$target_root/arm64"
env CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_TARGET_DIR="$arm64_dir" RUSTC="$rustc" \
  RUSTFLAGS="$base_rustflags" \
  "$cargo" build --locked --release --target aarch64-apple-darwin
artifacts+=("$arm64_dir/aarch64-apple-darwin/release/libpam_ssh_agent.dylib")

if [[ "$pointer_auth" == YES ]]; then
  arm64e_dir="$target_root/arm64e"
  arm64e_flags="${base_rustflags:+$base_rustflags }-Zbranch-protection=pac-ret,leaf,b-key"
  env CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_TARGET_DIR="$arm64e_dir" RUSTC="$rustc" \
    RUSTFLAGS="$arm64e_flags" \
    "$cargo" build --locked --release --target arm64e-apple-darwin \
      -Z build-std=std,panic_unwind
  arm64e_artifact="$arm64e_dir/arm64e-apple-darwin/release/libpam_ssh_agent.dylib"
  artifacts+=("$arm64e_artifact")
fi

if [[ "$checked_pointer" == YES ]]; then
  x1_dir="$target_root/arm64e-x1"
  x1_flags="${base_rustflags:+$base_rustflags }-Zbranch-protection=pac-ret,pc,b-key,leaf"
  x1_flags+=" -Ctarget-feature=+cpa,+mte,+pauth-lr,+fpac"
  x1_flags+=" -Cllvm-args=--aarch64-use-featcpa-codegen"
  env CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_TARGET_DIR="$x1_dir" RUSTC="$rustc" \
    CARGO_TARGET_ARM64E_APPLE_DARWIN_LINKER="$linker" \
    RUSTFLAGS="$x1_flags" \
    "$cargo" build --locked --release --target arm64e-apple-darwin \
      -Z build-std=std,panic_unwind
  x1_artifact="$x1_dir/arm64e-apple-darwin/release/libpam_ssh_agent.dylib"
  artifacts+=("$x1_artifact")
fi

mkdir -p "$(dirname -- "$output")"
staging_dir=$(mktemp -d "$(dirname -- "$output")/.macos-enhanced.XXXXXX")
temporary="$staging_dir/$(basename -- "$output")"
inspection_dir="$staging_dir/inspection"
mkdir "$inspection_dir"
cleanup() {
  rm -rf "$staging_dir"
}
trap cleanup EXIT

if [[ ${#artifacts[@]} == 1 ]]; then
  cp "${artifacts[0]}" "$temporary"
else
  xcrun lipo -create "${artifacts[@]}" -output "$temporary"
fi

if [[ -n ${CODE_SIGN_IDENTITY:-} ]]; then
  codesign --force --sign "$CODE_SIGN_IDENTITY" "$temporary"
fi

actual_architectures=$(xcrun lipo -archs "$temporary")
read -r -a actual_architecture_list <<<"$actual_architectures"
[[ ${#actual_architecture_list[@]} -eq ${#architectures[@]} ]] || {
  printf 'unexpected slices: %s\n' "$actual_architectures" >&2
  exit 1
}
for architecture in "${architectures[@]}"; do
  [[ " $actual_architectures " == *" $architecture "* ]] || {
    printf 'missing slice %s in: %s\n' "$architecture" "$actual_architectures" >&2
    exit 1
  }
done

symbols=$(xcrun nm -gU "$temporary")
grep -q '_pam_sm_authenticate$' <<<"$symbols"
grep -q '_pam_sm_setcred$' <<<"$symbols"
codesign --verify --strict "$temporary"

if [[ "$pointer_auth" == YES ]]; then
  arm64e_header=$(xcrun otool -hv "$arm64e_artifact")
  grep -q 'ARM64.*E' <<<"$arm64e_header"
  xcrun llvm-objdump --disassemble "$arm64e_artifact" >"$inspection_dir/arm64e.txt"
  grep -Eq '\b(pacibsp|retab)\b' "$inspection_dir/arm64e.txt"
fi

if [[ "$checked_pointer" == YES ]]; then
  x1_header=$(xcrun otool -hv "$x1_artifact")
  grep -q 'ARM64.*E\.X1' <<<"$x1_header"
  xcrun llvm-objdump --disassemble "$x1_artifact" >"$inspection_dir/arm64e-x1.txt"
  grep -Eq '\b(addpt|subpt|maddpt|msubpt)\b' "$inspection_dir/arm64e-x1.txt"
  grep -Eq '\b(pacibsppc|retabsppc)\b' "$inspection_dir/arm64e-x1.txt"
fi

chmod 0755 "$temporary"
mv -f "$temporary" "$output"
rm -rf "$staging_dir"
trap - EXIT

printf 'OUTPUT=%s\n' "$output"
xcrun lipo -info "$output"
xcrun otool -L "$output"
codesign -dv --verbose=4 "$output"
