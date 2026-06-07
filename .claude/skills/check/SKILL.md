---
name: check
description: Run the full local CI gate for pam-ssh-agent — formatting, build, tests under both crypto backends, and clippy. Use before pushing or opening a PR. Mirrors .github/workflows/rust.yml. There is no `make check` target despite the README; this is the replacement.
disable-model-invocation: true
---

# check

Run the same checks CI runs (`.github/workflows/rust.yml`), in order, from the repo root.
Run them all (don't stop at the first failure), then print a short summary table of each
step's result. For any failure, show the relevant failing output.

1. **Formatting** — `cargo fmt --check`
2. **Build** — `cargo build --verbose`
3. **Tests (pure-Rust crypto)** — `cargo test --no-default-features`
4. **Tests (OpenSSL / native-crypto)** — `cargo test --no-default-features --features native-crypto`
   - Needs `libssl-dev` + `libpam0g-dev` on Linux; on macOS OpenSSL must be discoverable
     (Homebrew `openssl@3`, e.g. via `OPENSSL_DIR`). If this step can't build because OpenSSL
     isn't found, report that distinctly — it's an environment gap, not a code failure.
5. **Lint** — `cargo clippy --no-deps`

Summary table columns: step, command, result (✅/❌/⚠️ skipped).
