# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **macOS-only** PAM authentication module (Rust, targeting OpenPAM) that proves a user's identity by having a (possibly remote, agent-forwarded) `ssh-agent` sign a random 32-byte challenge with a private key whose public key is trusted by this module. It is a clean-room re-implementation of `pam_ssh_agent_auth` and also supports SSH certificates. It compiles to a C-ABI shared library (`libpam_ssh_agent.dylib`, shipped as a thin **arm64e** Mach-O named `pam_ssh_agent.so`) loaded by macOS's PAM. See `README.md` for end-user configuration, PAM options, variable expansions, and the `sshd`/`SSH_AUTH_INFO_0` special case.

This is **security-sensitive software**: a bug can grant undue privilege escalation (this module gates `sudo`/`su`/`sshd` auth). The overriding design goals are robustness and reviewability — prefer clear, auditable code and lean on vetted upstream crates (`ssh-key`, `ssh-agent-client-rs`) rather than hand-rolling crypto or protocol logic.

## Commands

The crypto and PAM logic is architecture-independent, so correctness checks run on the **host** toolchain/arch:

```sh
cargo fmt --check        # formatting
cargo build              # default build (pure-Rust crypto)
cargo test               # unit + integration tests
cargo clippy --no-deps   # lint
```

A `Makefile` wraps these and the arm64e build:

```sh
make check    # cargo fmt --check, cargo clippy --no-deps, cargo test
make pam      # build the shippable arm64e dylib (toolchain overridable via PAM_TOOLCHAIN, default nightly)
make install  # make pam, then sudo install into /usr/local/lib/pam/pam_ssh_agent.so
make clean    # cargo clean
```

The **shippable** artifact is a thin **arm64e** dylib. `arm64e-apple-darwin` is a tier-3 Rust target with no prebuilt `std`, so it needs a **nightly** toolchain plus `-Zbuild-std`:

```sh
make pam   # pins nightly's rustc via `rustup which` (Homebrew's stable rustc otherwise
           # shadows it in PATH and gets fed -Z, which only nightly accepts)
# in effect: rustup run nightly cargo build -Z build-std=std --release --target arm64e-apple-darwin
# -> target/arm64e-apple-darwin/release/libpam_ssh_agent.dylib  (thin arm64e, ad-hoc signed)
```

**Gotcha:** third-party arm64e *executables* cannot run under Apple's preview-ABI gate, so `cargo test` (test binaries) runs on the **host** arch — only the shipped dylib is arm64e.

Running specific tests / examples:

```sh
cargo test test_roundtrip          # a single test by name
cargo test --test sk_not_present   # one integration test file (tests/*.rs)
cargo test -- --ignored            # #[ignore]d tests that require root (e.g. uid-drop in cmd.rs)

# Smoke-test against a real running ssh-agent (SSH_AUTH_SOCK must be set):
cargo run --example authenticator -- tests/data/authorized_keys
cargo run --example testdata -- <pubkey>   # generates signature test vectors
```

Requires Rust 1.88+ (edition 2024) for host-arch checks; nightly for the arm64e module.

## Architecture

**PAM entry → authentication flow.** The PAM FFI lives in `src/openpam.rs` (this fork's own bindings, which **replaced** the `pam-bindings` crate). It exports exactly two C entry points — `pam_sm_authenticate` and `pam_sm_setcred` — each wrapped in `catch_unwind` so a Rust panic cannot unwind into the PAM host. Constants come from the macOS SDK `security/pam_constants.h`; note OpenPAM numbers result codes differently from Linux-PAM (**`PAM_AUTH_ERR=9`** vs 7; only `PAM_SUCCESS=0` agrees). `sm_authenticate` delegates to `run()` → `do_authenticate()`, which resolves the agent socket (`SSH_AUTH_SOCK` or the `default_ssh_auth_sock` arg), builds an `IdentityFilter`, checks the `sshd` special case, then calls `authenticate()`. Every error is logged and collapsed to `PAM_AUTH_ERR`; only the happy path returns `PAM_SUCCESS`. `sm_setcred` is a deliberate no-op that returns success.

**Challenge-response core** (`src/auth.rs::authenticate`). Lists identities the agent holds, keeps only those the filter trusts, and for each: if it's a certificate, runs `validate_cert` (validity window, signature by a trusted CA fingerprint, user-certificate type, requesting principal present, no unknown critical options); then signs a fresh 32-byte random challenge and verifies the signature locally. A `RemoteFailure` from the agent (e.g. a hardware/`sk` key that is configured but not currently plugged in) is **not** fatal — it moves on to the next key. This "try next key" behavior is exactly what `tests/sk_not_present.rs` exercises; preserve it.

**Trust configuration** (`src/filter.rs::IdentityFilter`). Holds two `HashSet<KeyData>`: plain authorized keys and `cert-authority` keys. Sources, in combination: the `file=` authorized_keys file, a `ca_keys_file=` (raw CA keys, no prefix, OpenSSH `TrustedUserCAKeys`-style), and/or an `authorized_keys_command=` whose stdout is parsed as authorized_keys. The `cert-authority` option prefix in an authorized_keys line routes a key into the CA set.

**Signature verification** (`src/verify.rs`). `verify()` uses `ssh-key`'s pure-Rust `signature::Verifier` over `KeyData`. (Upstream had an optional OpenSSL `native-crypto` backend for FIPS-mandated Linux distros; this macOS-only fork **removed** it along with `src/nativecrypto.rs`.)

**Testability via trait seams.** External, hard-to-test dependencies are abstracted behind small traits so tests can inject fakes:
- `SSHAgent` (`src/agent.rs`) wraps `ssh_agent_client_rs::Client` (`list_identities`, `sign`).
- `Environment` (`src/environment.rs`) wraps OS lookups (homedir, hostname, fqdn, uid, env vars); `UnixEnvironment` is the real impl.
- `PamHandleExt` (`src/pamext.rs`) adds `get_calling_user` (PAM_USER) and `get_service` (PAM_SERVICE) to the PAM handle.

`src/test.rs` (gated `#[cfg(test)]`) provides the fakes — `CannedEnv`/`CannedHandler` (queue of canned answers), `DummyEnv`/`DummyHandle` (panic if called) — and the `data!` macro for test-data paths. New testable logic should follow this pattern: take a trait, not the concrete type.

**Supporting modules.** `src/args.rs` parses space-separated PAM `key=value` options. `src/expansions.rs` handles the `~`/`%h`/`%H`/`%f`/`%u`/`%U` substitutions applied to option values. `src/cmd.rs` runs external commands with a 10s timeout and optional uid-drop (used by `authorized_keys_command_user`). `src/logging.rs` sends `log` macros to the `AUTHPRIV` syslog facility with a `pam_ssh_agent(<service>:auth):` prefix matching the original module; init is idempotent (guarded by a mutex) and best-effort (falls back to stderr, never fails auth).

## Conventions & gotchas

- **Tests resolve paths two different ways.** Compile-time paths via the `data!` macro / `include_str!` resolve from `$CARGO_MANIFEST_DIR/tests/data/`, but runtime file paths in integration tests are written relative to the repo root (e.g. `"tests/data/authorized_keys"`), so `cargo test` must be run from the project root. Regenerate test keys/certs per the recipe in `tests/data/README.md`.
- **Certificates must have a bounded expiry** (upstream `ssh-key` limitation). A genuine no-expiry cert (`valid before` = `u64::MAX`, what `ssh-keygen` emits by default / `always:forever`) is rejected *at parse time* by `ssh-key` 0.6.7 and never reaches `validate_cert`. [RustCrypto/SSH#174](https://github.com/RustCrypto/SSH/issues/174) raised the cap only to `i64::MAX`, so a far-future expiry works but a true forever cert does not. Verified by the `test_no_expiry_cert_is_rejected_by_ssh_key` regression test (vector `tests/data/cert_forever.pub`); see the note in `README.md`. Don't assume non-expiring certs work yet.
- **Home-directory (`~`/`%h`) expansion is intentionally unsafe** and documented as such — do not extend or "improve" it toward making attacker-controlled key files easier to use. (`%H`/`%f` use `gethostname()`, which on macOS changes with the network/Bonjour, so templated key paths can be unstable.)
- **macOS PAM specifics matter** — OpenPAM result codes are numbered differently from Linux-PAM (**`PAM_AUTH_ERR=9`**, not 7); `/usr/lib/pam` is SIP-protected (install to `/usr/local/lib/pam` and reference by absolute path in `/etc/pam.d`); PAM hosts (`sudo`/`su`/`sshd`) are arm64e; and the `authorized_keys_command` privilege drop targets the macOS `nobody` account (uid/gid `(gid_t)-2` = `4294967294`), not the Linux overflow gid 65534. See `AUDIT.md` for the full audit and findings.
- **The `sshd`/`SSH_AUTH_INFO_0` "sufficient" shortcut is likely inert on macOS** — macOS `sshd`'s `ExposeAuthInfo` exposes `SSH_USER_AUTH` (a path to a file), not the inline `SSH_AUTH_INFO_0` that `check_sshd_special_case` reads, so the shortcut won't fire and auth falls through to the normal challenge-response (fail-safe). Retained from the `pam_ssh_agent_auth` lineage; verified against `sshd_config(5)` — see `AUDIT.md`. (Separately, on macOS 26+/Tahoe `sshd-session` is a platform binary that may refuse to map a non-platform PAM module at all — to be confirmed live; the module is realistically scoped to `sudo`/`su`.)
- **`panic = "unwind"` is load-bearing — never set `panic = "abort"`.** The two C entry points (`src/openpam.rs` / `src/lib.rs`) wrap their bodies in `catch_unwind` to turn a Rust panic into `PAM_AUTH_ERR`; with `panic = "abort"` there is nothing to catch and a panic would `SIGABRT` the host (`sudo`/`su`/`sshd`) mid-auth. `[profile.release]` in `Cargo.toml` pins `panic = "unwind"` (with `overflow-checks = true` so a parser wraparound fails closed) — keep it. For the same fail-open-never reason, the logging locks in `src/logging.rs` recover from poisoning (`lock().unwrap_or_else(|e| e.into_inner())`) rather than `.unwrap()`-panicking.
- **arm64e LINKEDIT alignment workaround — `make pam` post-processes the dylib.** The `ld-1328.2` linker (Xcode 26, mid-2026) lays out the `LC_SYMTAB` string table at a **4-byte**-aligned file offset; macOS 26/Tahoe dyld requires **8-byte** alignment and refuses to `dlopen` the image (`mis-aligned LINKEDIT string pool`), so the raw `cargo build -Z build-std` arm64e dylib **will not load into `sudo`/`su`** (verified: it fails to load even in a plain arm64e test process, while a trivial arm64e dylib loads fine). `make pam` therefore runs `scripts/realign-linkedit.py` after the build (idempotent: inserts ≤7 zero bytes of LINKEDIT padding, fixes `LC_SYMTAB.stroff`/`__LINKEDIT` size, re-signs ad-hoc). `make verify-load` `dlopen`s the result in an arm64e process to confirm both entry points resolve. Drop the workaround once the toolchain emits an 8-aligned string table (the script no-ops then). See `AUDIT.md`.
