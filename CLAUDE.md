# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **macOS-only** PAM authentication module (Rust, targeting OpenPAM) that proves a user's identity by having a (possibly remote, agent-forwarded) `ssh-agent` sign a random challenge with a private key whose public key is trusted by this module. It is a clean-room re-implementation of `pam_ssh_agent_auth` and also supports SSH certificates. It compiles to a C-ABI shared library (`libpam_ssh_agent.dylib`, shipped as an **arm64e** module named `pam_ssh_agent.so`) loaded by macOS's PAM. See `README.md` for end-user configuration, PAM options, variable expansions, and the `sshd`/`SSH_AUTH_INFO_0` special case.

This is **security-sensitive software**: a bug can grant undue privilege escalation. The overriding design goals are robustness and reviewability — prefer clear, auditable code and lean on vetted upstream crates (`ssh-key`, `ssh-agent-client-rs`, `pam-bindings`) rather than hand-rolling crypto or protocol logic.

## Commands

There is **no Makefile** despite `README.md` mentioning `make check`. Run the checks individually — these mirror CI (`.github/workflows/rust.yml`):

```sh
cargo fmt --check        # formatting (CI fails on diffs)
cargo build              # default build (pure-Rust crypto)
cargo test               # unit + integration tests
cargo clippy --no-deps   # lint

# Host-arch debug artifact: target/debug/libpam_ssh_agent.dylib
cargo build --release
```

The crypto/PAM logic is architecture-independent, so `cargo build`/`cargo test` run on the host
toolchain. The **shippable** artifact is a thin **arm64e** dylib (see P4/Makefile in later
phases) — arm64e is a tier-3 Rust target requiring nightly + `-Zbuild-std`.

Running specific tests / examples:

```sh
cargo test test_roundtrip          # a single test by name
cargo test --test sk_not_present   # one integration test file (tests/*.rs)
cargo test -- --ignored            # #[ignore]d tests that require root (e.g. uid-drop in cmd.rs)

# Smoke-test against a real running ssh-agent (SSH_AUTH_SOCK must be set):
cargo run --example authenticator -- tests/data/authorized_keys
cargo run --example testdata -- <pubkey>   # generates signature test vectors
```

Requires Rust 1.88+ (edition 2024) for host-arch checks; nightly for the arm64e module. macOS only.

## Architecture

**PAM entry → authentication flow.** `src/lib.rs` registers the module via `pam::pam_hooks!`. `sm_authenticate` is the real entry point; it delegates to `run()` → `do_authenticate()`, which: resolves the agent socket (`SSH_AUTH_SOCK` or the `default_ssh_auth_sock` arg), builds an `IdentityFilter`, checks the `sshd` special case, then calls `authenticate()`. Every error is logged and collapsed to `PAM_AUTH_ERR`; only the happy path returns `PAM_SUCCESS`. `sm_setcred` is a deliberate no-op that returns success (required so `doas` doesn't error).

**Challenge-response core** (`src/auth.rs::authenticate`). Lists identities the agent holds, keeps only those the filter trusts, and for each: if it's a certificate, runs `validate_cert` (validity window, signature by a trusted CA fingerprint, requesting principal present, no unknown critical options); then signs a fresh 32-byte random challenge and verifies the signature locally. A `RemoteFailure` from the agent (e.g. a hardware/`sk` key that is configured but not currently plugged in) is **not** fatal — it moves on to the next key. This "try next key" behavior is exactly what `tests/sk_not_present.rs` exercises; preserve it.

**Trust configuration** (`src/filter.rs::IdentityFilter`). Holds two `HashSet<KeyData>`: plain authorized keys and `cert-authority` keys. Sources, in combination: the `file=` authorized_keys file, a `ca_keys_file=` (raw CA keys, no prefix, OpenSSH `TrustedUserCAKeys`-style), and/or an `authorized_keys_command=` whose stdout is parsed as authorized_keys. The `cert-authority` option prefix in an authorized_keys line routes a key into the CA set.

**Signature verification** (`src/verify.rs`). `verify()` uses `ssh-key`'s pure-Rust `signature::Verifier` over `KeyData`. (Upstream had an optional OpenSSL `native-crypto` backend for FIPS-mandated Linux distros; this macOS-only fork removed it along with `src/nativecrypto.rs`.)

**Testability via trait seams.** External, hard-to-test dependencies are abstracted behind small traits so tests can inject fakes:
- `SSHAgent` (`src/agent.rs`) wraps `ssh_agent_client_rs::Client` (`list_identities`, `sign`).
- `Environment` (`src/environment.rs`) wraps OS lookups (homedir, hostname, fqdn, uid, env vars); `UnixEnvironment` is the real impl.
- `PamHandleExt` (`src/pamext.rs`) adds `get_calling_user` (PAM_USER) and `get_service` (PAM_SERVICE) to `PamHandle`.

`src/test.rs` (gated `#[cfg(test)]`) provides the fakes — `CannedEnv`/`CannedHandler` (queue of canned answers), `DummyEnv`/`DummyHandle` (panic if called) — and the `data!` macro for test-data paths. New testable logic should follow this pattern: take a trait, not the concrete type.

**Supporting modules.** `src/args.rs` parses space-separated PAM `key=value` options. `src/expansions.rs` handles the `~`/`%h`/`%H`/`%f`/`%u`/`%U` substitutions applied to option values. `src/cmd.rs` runs external commands with a 10s timeout and optional uid-drop (used by `authorized_keys_command_user`). `src/logging.rs` sends `log` macros to the `AUTHPRIV` syslog facility with a `pam_ssh_agent(<service>:auth):` prefix matching the original module; init is idempotent (guarded by a mutex).

## Conventions & gotchas

- **Tests resolve paths two different ways.** Compile-time paths via the `data!` macro / `include_str!` resolve from `$CARGO_MANIFEST_DIR/tests/data/`, but runtime file paths in integration tests are written relative to the repo root (e.g. `"tests/data/authorized_keys"`), so `cargo test` must be run from the project root. Regenerate test keys/certs per the recipe in `tests/data/README.md`.
- **Certificates currently must have an expiry** (upstream `ssh-key` bug); see the note in `README.md`. Don't assume non-expiring certs work yet.
- **Home-directory (`~`/`%h`) expansion is intentionally unsafe** and documented as such — do not extend or "improve" it toward making attacker-controlled key files easier to use.
- **macOS PAM specifics matter** — OpenPAM numbers result codes differently from Linux-PAM (e.g. `PAM_AUTH_ERR=9`, not 7), `/usr/lib/pam` is SIP-protected, and PAM hosts (`sudo`/`su`/`sshd`) are arm64e. See `AUDIT.md` for the full list.
