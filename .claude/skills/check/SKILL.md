---
name: check
description: Run the full local CI gate for pam-ssh-agent — formatting, build, tests, and clippy on the host toolchain/arch. Use before pushing or opening a PR. Equivalent to `make check`; building the shipped arm64e module is a separate step (`make pam`).
disable-model-invocation: true
---

# check

Run the host-arch correctness gate, in order, from the repo root. The crypto and PAM logic
is architecture-independent, so these run on the host toolchain (no arm64e cross-build needed).
Run them all (don't stop at the first failure), then print a short summary table of each
step's result. For any failure, show the relevant failing output.

1. **Formatting** — `cargo fmt --check`
2. **Build** — `cargo build --verbose`
3. **Tests** — `cargo test`
4. **Lint** — `cargo clippy --no-deps`

`make check` runs steps 1, 3, and 4 as a shorthand. Note this gate does **not** produce the
shippable artifact: the thin arm64e dylib (`pam_ssh_agent.so`) is built separately with
`make pam` (a nightly `-Z build-std` cross-build for `arm64e-apple-darwin`).

Summary table columns: step, command, result (✅/❌/⚠️ skipped).
