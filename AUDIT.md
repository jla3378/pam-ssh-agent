# macOS debug & audit of `pam-ssh-agent`

This document records an audit of `pam-ssh-agent` aimed at running the module on **macOS**
(which uses OpenPAM, not Linux-PAM) and reviewing the authentication / certificate /
verification logic. The changes here sit on top of upstream `main` (v0.9.7).

## Headline result: macOS already builds — no link fix needed

An earlier draft of this audit added a `build.rs` emitting `-undefined dynamic_lookup`, on the
assumption that the `cdylib` would otherwise fail to link on macOS with
`Undefined symbols: _pam_get_item`. **Auditing against a live macOS install disproved that:**

* `cargo build --release` **succeeds with no build script** — verified by removing `build.rs`
  and rebuilding (clean relink, exit 0, `.dylib` produced).
* `pam-bindings` declares `#[link(name = "pam")]` (in both 0.1.1 and the current 0.3.0), so the
  linker pulls in `/usr/lib/libpam.2.dylib` and `pam_get_item` resolves at link time;
  `otool -L` on the artifact confirms the `libpam.2.dylib` dependency.

The `build.rs` was therefore **removed** as unnecessary. macOS support is otherwise a
documentation matter (the artifact is a `.dylib`; install outside the SIP-protected
`/usr/lib/pam`); see `README.md` → "Building and installing on macOS".

## Environment & verification

Performed on macOS 26.5.1 (arm64), MSRV 1.88. Both crypto backends:

| Check | Result |
|-------|--------|
| `cargo build --release` (default, no build.rs) | ✅ links + produces `libpam_ssh_agent.dylib` |
| `cargo test --no-default-features` | ✅ pass |
| `cargo test --no-default-features --features native-crypto` | ✅ pass (OpenSSL) |
| `cargo fmt --check` / `cargo clippy --no-deps` | ✅ clean |

Not exercised: loading the `.dylib` into a live OpenPAM stack and authenticating end-to-end
(needs root + a configured `/etc/pam.d` service + a key-bearing agent).

## Findings & fixes

### FIX A — `SSH_AUTH_INFO_0` parsed incorrectly for the sshd special case — Medium (correctness, cross-platform)
* **Where:** `src/lib.rs::check_sshd_special_case`.
* **Problem:** the code ran `PublicKey::from_openssh()` on the raw `SSH_AUTH_INFO_0` value, but
  `sshd` formats each entry with a leading method token (`publickey ssh-ed25519 AAAA…`).
  Parsing always failed, so the documented sshd `sufficient` shortcut never fired, and the
  parse error short-circuited the normal challenge-response path too. (Fail-safe: a
  `sufficient` module that errors is skipped by PAM, so this was a broken feature, not a bypass.)
* **Fix:** strip the leading `publickey ` token (tolerating its absence), iterate entries, parse
  each as a certificate or a plain public key by key type, route certificates through the full
  `validate_cert` check, and treat parse failures as non-fatal. Requires exposing
  `validate_cert` (`pub(crate)`).
* **Test:** `tests::test_check_sshd_special_case`.

### FIX B — logging setup could deny authentication — Low / defensive
* **Where:** `src/lib.rs::run` → `src/logging.rs`.
* **Problem:** `run()` propagated `init_logging` failures to `PAM_AUTH_ERR`, so if the syslog
  socket were unavailable, authentication would fail closed.
* **Live note:** on macOS `init_logging` actually **succeeds** — `/var/run/syslog` exists (only
  `/dev/log` and `/var/run/log`, which `syslog::unix()` also probes, are absent). So this is a
  defensive hardening, not a macOS blocker.
* **Fix:** `init_logging` is best-effort at the call site (log to stderr, continue).

### Dropped — macOS cdylib link fix
See "Headline result" — `build.rs` was removed; it is not needed.

### Dropped — certificate-type check
A user-vs-host certificate check found during the audit was **already fixed upstream**
(`8e21d5e`, "Ensure that only user certificates can be used to authenticate"), so it is not
duplicated here.

## Reviewed and assessed OK (no change)

* **Challenge-response core** (`authenticate` / `sign_and_verify`): signs a fresh 32-byte random
  challenge and verifies locally; a `RemoteFailure` (e.g. an `sk`/hardware key not present) is
  non-fatal and tries the next key.
* **Certificate validation** (`validate_cert`): window, CA-fingerprint signature, user-cert type
  (upstream), principal membership, empty critical options.
* **Crypto-backend parity** (`src/verify.rs` ↔ `src/nativecrypto.rs`): Ed25519, ECDSA
  P-256/384/521, RSA-SHA256/512; fail closed otherwise.

## Notes

* **PAM result-code numbering** differs between Linux-PAM and OpenPAM (`pam-bindings` uses the
  Linux values). Fail-safe here: only the happy path returns `PAM_SUCCESS` (`0`, which agrees
  across both), and every error path is non-zero, which PAM treats as failure regardless of the
  exact number.

## Remaining (user, on a Mac)

1. Install per `README.md` → "Building and installing on macOS".
2. Wire into a test `/etc/pam.d` service (e.g. `sudo_local`) and authenticate via an agent such
   as Secretive (`SSH_AUTH_SOCK`).
