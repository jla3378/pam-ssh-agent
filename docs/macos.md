# macOS installation

This module supports Apple OpenPAM on arm64 macOS.
Use the default Rust crypto implementation.
The module reads the current `SSH_AUTH_SOCK`.

For a privileged sudo deployment, use the strict profile and an explicit per-user trust file:

```text
auth sufficient /nix/store/…-pam-ssh-agent-…/lib/security/pam_ssh_agent.so strict agent_timeout=30 file=/etc/security/pam-ssh-agent/%u
```

Strict mode disables the legacy `sshd` environment shortcut unless `sshd_shortcut` is explicitly added. It rejects
home-expanded trust paths, dynamic helper paths, unsupported authorized-keys options, and trust files that are not
root-controlled. A helper executable must also be root-controlled. The helper environment, output limit, process-group
cleanup, and deadline are bounded as described in the main README. A strict helper must run as a non-root account and
cannot create child processes.

## Build and inspect

Run these commands from the source directory:

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --locked --release
cargo bench --bench per_request --locked
xcrun nm -gU target/release/libpam_ssh_agent.dylib
xcrun otool -L target/release/libpam_ssh_agent.dylib
codesign --verify --strict target/release/libpam_ssh_agent.dylib
codesign -dv --verbose=4 target/release/libpam_ssh_agent.dylib
```

The benchmark reports p50, p95, and p99 for policy loading and in-process authentication with one or four identities.
The authentication cases include selection, challenge generation, fixture-backed signing, and verification. They exclude
Unix-socket IPC, a real or hardware-backed agent, allocations, and resident memory. The harness does not cache filters
between requests or replace a live agent test.

The tests compile SDK constants and use real PAM handles.
The agent fixture uses a public test key and tests successful, untrusted, and denied signatures.
It also tests unavailable sockets, missing items, invalid arguments, panic containment, and credential setup.
Tests that create Unix sockets need permission to create local sockets.
Two existing tests require root and remain ignored during normal test runs.

## Install through nix-atlas

Pin an immutable source commit and use Cargo.lock.
Install `libpam_ssh_agent.dylib` as `lib/security/pam_ssh_agent.so` in the package.
Use the absolute package path in `security.pam.services.sudo_local.text`.

Keep this order:

```text
auth optional /nix/store/…-pam_reattach-…/lib/pam/pam_reattach.so
auth sufficient /nix/store/…-pam-ssh-agent-…/lib/security/pam_ssh_agent.so strict agent_timeout=30 file=/etc/security/pam-ssh-agent/%u
auth sufficient pam_tid.so
```

Keep Apple's `/etc/pam.d/sudo` unchanged.
Its `sudo_local` include precedes the password fallback.
Do not replace the Nix-managed `sudo_local` symlink manually.

Keep one sudoers declaration:

```sudoers
Defaults env_keep += "SSH_AUTH_SOCK"
```

Select each trusted public key by its SHA256 fingerprint.
Store selected keys in `/etc/security/pam-ssh-agent/<username>`.
Keep the file and its parent directories under root control.
A root-owned Nix store file through `/etc/static` meets this requirement.
Never copy every agent identity into the trusted file.

Build the package and system before activation.
Inspect PAM order, the key fingerprint, file ownership, and sudoers syntax.
Record the current generation before activation.
Run privileged commands in a user-created `agent-*` tmux session with approval for each command.
Keep a separate administrative session available during validation.

## Diagnose

```sh
ssh-add -l
ssh-keygen -lf ~/.ssh/id_ed25519.pub
csrutil status
log show --last 5m --style compact --predicate 'eventMessage CONTAINS "pam_ssh_agent"'
```

A key must be both loaded in the current agent and present in the trusted file.
Use `ssh-add ~/.ssh/id_ed25519` to load the selected key.
Enter the passphrase in the terminal if required.
Never record the passphrase or private key.

Use `/usr/bin/sudo -k` before every live authentication test.
Do not use `sudo -n` for this test.
Apple sudo skips PAM for noninteractive authentication unless `noninteractive_auth` is enabled.
Confirm module success in the logs; another sufficient PAM module can also succeed.
Test fallback with an absent socket, an untrusted key, and a denied signing request.
Confirm a fresh Touch ID or password authentication after each failure.
The unprivileged PAM tests do not prove Apple's sudo can load the installed module.

Inspect the generated configuration before activation. Confirm the module path is an immutable Nix store path, the
strict option and timeout are present, and the selected key file contains only the fingerprint you approved. Keep the
existing `pam_reattach` line before this module and `pam_tid.so` after it. A successful trusted-key attempt should stop
at the sufficient module; an absent socket, untrusted key, or denied signing request must continue to Apple's Touch ID
and password fallback.

## Roll back

Record the previous `/nix/var/nix/profiles/system-<number>-link` before activation.
Use the installed `darwin-rebuild --switch-generation <number>` command after approval.
Compare `/etc/pam.d/sudo_local` with the previous generation.
Confirm a fresh Touch ID or password authentication.
Rebuild and activate the desired configuration when rollback validation is complete.

Record the active generation and the result of `csrutil status` in the handoff. The xctrace command-line workflow for
capturing per-request profiles is unverified because the Xcode documentation source gate was unavailable. The installed
toolchain used for this work is Xcode 27.0 (27A266a) with macOS SDK 27.0. If profiling is needed, first capture a
non-privileged baseline with the installed Instruments or xctrace tools and record the exact command and output before
using it to guide changes.

## Source evidence

Xcode DocumentationSearch did not return the OpenPAM declarations.
The installed headers supply the constants and signatures:
`MacOSX27.0.sdk/usr/include/security/pam_constants.h`, `pam_modules.h`, and `pam_appl.h`.
The developer directory is `/Applications/Xcode.app/Contents/Developer`.
The toolchain is Xcode 27.0 (27A266a), macOS SDK 27.0, arm64-apple-darwin.
[Apple XNU `kern_prot.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c)
and [`kern_credential.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_credential.c)
show that `setgroups(0, NULL)` disables the external group resolver and that the following `setgid` sets the only
credential group to the target GID. [Apple `id.c`](https://github.com/apple-oss-distributions/shell_cmds/blob/main/id/id.c)
shows that `id -G` uses `getgrouplist_2` for the current account. The SDK maps modern `getgroups` callers to the
extended symbol. [Apple Libc `getgroups.c`](https://github.com/apple-oss-distributions/Libc/blob/main/sys/getgroups.c)
shows that this symbol also resolves the account group list. The root-only test dynamically resolves the unversioned
`getgroups` symbol when it checks the stored child credential list on macOS.
The live `/etc/pam.d/sudo` supplies the observed fallback order.
On 2026-09-21, fresh Apple `/usr/bin/sudo -k` tests exercised the module built from public commit
`19cb50be449ab507036ffc3c473186186e7516ab`. The trusted-key case returned UID 0 immediately. This result is an
inference from the controlled failure cases because normal success logging is debug-level and no module-specific success
event appeared in the unified log. Absent-socket, untrusted-key, and denied-signing tests returned UID 0 through the
downstream Apple fallback.

Rollback to generation 49 restored the earlier non-strict module and removed the hardening provenance while preserving
the selected key and sudoers declaration. Reactivation installed generation 51 at
`/nix/store/2jx7jjv8y92z2njsdcqczf0zaxw9wi96-darwin-system-26.11.15abb8c`. Its post-activation gate, fresh trusted-key
test, missing-socket fallback test, and SIP check passed. Both generation commands applied PAM and `/etc` before existing
Homebrew hook failures caused status 1.

On 2026-09-22, the 200-sample benchmark reported policy-load p50 12.458 µs, p95 15.5 µs, and p99 24.5 µs. In-process
authentication reported p50 60.292 µs, p95 68.458 µs, and p99 73.25 µs with one identity, and p50 60.667 µs, p95
68.25 µs, and p99 76.417 µs with three decoys followed by the match. These measurements exclude Unix-socket IPC and
hardware-backed user presence.
