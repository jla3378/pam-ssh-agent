# macOS installation

The selected macOS production profile is defined in
[macOS support contract](macos-support.md) and
[support/macos/release-profile.toml](../support/macos/release-profile.toml).
See the [PAM boundary audit](pam-boundary-audit.md) for the threat model and
qualification record.
It targets Apple OpenPAM on arm64 macOS, uses the default Rust crypto implementation, and reads the current
`SSH_AUTH_SOCK`.

The broader build and runtime behavior described below is reference material until it has been qualified against that
contract. A successful local build or direct PAM test does not qualify Apple's sudo integration.

For a privileged sudo deployment, use the strict profile and an explicit per-user trust file. Replace the module path
with the path supplied by the package or installation method:

```text
auth sufficient /usr/local/lib/security/pam_ssh_agent.so strict agent_timeout=30 file=/etc/security/pam-ssh-agent/%u
```

Strict mode disables the legacy `sshd` environment shortcut unless `sshd_shortcut` is explicitly added. It rejects
home-expanded trust paths, dynamic helper paths, unsupported authorized-keys options, and trust files that are not
root-controlled. A helper executable must also be root-controlled. The helper environment, output limit, process-group
cleanup, and deadline are bounded as described in the main README. A strict helper must run as a non-root account and
cannot create child processes.

The strict trust file must use an absolute, byte-for-byte normalized path. The
loader validates lexical parent authority, then permits safe root-owned
intermediate aliases such as `/etc` while walking from `/` with descriptor-
relative `openat`, `O_NOFOLLOW`, and `O_RESOLVE_BENEATH`. It rejects a final
symlink. Every opened parent must be uid 0, a directory, free of group/world
write permission, and free of an extended ACL. The final object must be uid 0,
regular, mode `0600`, single-link, and free of an extended ACL. `O_UNIQUE`
rejects hard links. The bounded read revalidates the file and all opened parent
descriptors after the read; replacement, truncation, writes, ACL changes, and
other mutations fail closed. The root OpenPAM loader boundary is verified for
the recorded release artifact. Apple `/usr/bin/sudo` loading and the live sudo
path remain unverified until their release gates pass.

## Build and inspect

Run these commands from the source directory:

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --locked --release
PAM_LOADER_MODULE="$PWD/target/release/libpam_ssh_agent.dylib" \
  cargo test --locked --test macos_dylib_load -- \
    --ignored --exact release_dylib_is_accepted_by_dyld --nocapture
cargo bench --bench per_request --locked
xcrun nm -gU target/release/libpam_ssh_agent.dylib
xcrun otool -L target/release/libpam_ssh_agent.dylib
codesign --verify --strict target/release/libpam_ssh_agent.dylib
codesign -dv --verbose=4 target/release/libpam_ssh_agent.dylib
```

The release profile keeps Rust from stripping the linked Mach-O. Rust 1.96.1's
debug-information stripping can produce a string-table offset that macOS 27
rejects. Run the dyld preflight against the final bytes before any privileged
loader test. If packaging strips the library, use Apple's `/usr/bin/strip -S`,
then repeat the preflight and sign the resulting bytes.

### Optional Enhanced Security build

The standard build remains the default. The opt-in build helper is
`./scripts/build-macos-enhanced.sh`.

Set these switches only when the matching slice or security mode is required:

```sh
ENABLE_ENHANCED_SECURITY=YES \
ENABLE_POINTER_AUTHENTICATION=YES \
ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE=YES \
./scripts/build-macos-enhanced.sh
```

`ENABLE_ENHANCED_SECURITY` enables strong stack protection and release-mode overflow checks. Pointer authentication
defaults to the enhanced security setting. `ENABLE_POINTER_AUTHENTICATION=YES` adds an `arm64e` slice.
`ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE=YES` adds an `arm64e.x1` slice. `arm64` is always included. Each
setting accepts `YES` or `NO` and defaults to `NO` unless stated above. The helper rejects unsupported values.

The supported output matrix is:

| Settings | Slices |
| --- | --- |
| default | `arm64` |
| pointer authentication | `arm64`, `arm64e` |
| checked pointer arithmetic | `arm64`, `arm64e.x1` |
| both options | `arm64`, `arm64e`, `arm64e.x1` |

The `arm64e` and `arm64e.x1` builds use nightly Rust and `build-std` because Rust support for
`arm64e-apple-darwin` is Tier 3. The toolchain must include `rust-src`. Set `MACOS_ENHANCED_RUST_TOOLCHAIN` to a pinned
Rust toolchain for reproducible packaging. The x1 code-generation features are unstable Rust interfaces. The helper
therefore verifies the Mach-O subtype and checks the generated code for CPA2 and PAC instructions. It also reports the
selected Rust, Xcode, and SDK versions. An x1 build can be inspected on older Apple silicon, but it needs CPA2-capable
hardware for a run-time test.

The reference settings are in [support/macos/EnhancedSecurity.xcconfig](../support/macos/EnhancedSecurity.xcconfig).
The reference entitlements are in [support/macos/enhanced-security.entitlements](../support/macos/enhanced-security.entitlements).
They are examples only and are unused by default.

The entitlement dependency set is:

```text
com.apple.security.hardened-process = true
com.apple.security.hardened-process.enhanced-security-version-string = 2
com.apple.security.hardened-process.checked-allocations = true
com.apple.security.hardened-process.checked-allocations.enforce-checked-pointer-arithmetic-overflow = true
```

The Enhanced Security capability requires the hardened-process entitlement and version string. Checked pointer
arithmetic also requires the checked-allocations entitlement. These entitlements belong on a compatible host
executable. Code signing does not preserve them on this dynamic library, and dylib entitlements cannot change the
entitlements of Apple `/usr/bin/sudo`. The sample therefore documents host integration; it does not claim that the
SIP-protected sudo process enables these run-time checks. The helper accepts a code-signing identity for the library,
but it intentionally does not pass host entitlements to the library signature.

The benchmark reports p50, p95, and p99 for policy loading and in-process authentication with one or four identities.
The authentication cases include selection, challenge generation, fixture-backed signing, and verification. They exclude
Unix-socket IPC, a real or hardware-backed agent, allocations, and resident memory. The harness does not cache filters
between requests or replace a live agent test.

The tests compile SDK constants and use real PAM handles.
The agent fixture uses a public test key and tests successful, untrusted, and denied signatures.
It also tests unavailable sockets, missing items, invalid arguments, panic containment, and credential setup.
Tests that create Unix sockets need permission to create local sockets.
Tests that require root remain ignored during normal test runs.

## Qualification harnesses

The adversarial agent suite exercises malformed, truncated, oversized, wrong-type, duplicate, trailing-data,
disconnect, reset, fragmented, slow, replay, wrong-key, wrong-algorithm, invalid-signature, and impossible-count
responses. It also checks bytewise short reads and writes and retry after one duplicate-identity failure:

```sh
cargo test --locked --test macos_agent_adversarial -- --nocapture
```

The OpenPAM loader suite stages a unique PAM service, loads the built module through `pam_start`, and checks
success, untrusted and denied signatures, malformed and unknown options, absent sockets, repeated handles,
credential flags, invalid flags, concurrent handles, resource counts, and cleanup. It requires root because it writes
temporary entries below `/private/etc`; run the exact test binary from a user-created `agent-*` tmux session with the
module path and local account supplied by the operator:

```sh
cargo test --locked --test macos_loader --no-run
/usr/bin/sudo -k /usr/bin/env \
PAM_LOADER_MODULE=/absolute/path/to/libpam_ssh_agent.dylib \
PAM_LOADER_USER=local-account \
/absolute/path/to/macos_loader-<hash> --ignored --exact openpam_dynamic_loader_qualification --nocapture
```

Run the unprivileged dyld preflight from the build section before this command. The loader command is a qualification
step, not a normal unprivileged test. The recorded root run passed for the
selected release artifact through real `pam_start`, `pam_authenticate`,
`pam_setcred`, and `pam_end` handles. Apple sudo loading, fresh trusted-key
authentication, live fallback, and rollback remain unverified. The public
source tree does not include a machine-specific module path, trust file, key
fingerprint, or package configuration.

## Install

Build the release artifact, then install it using the package or configuration system used by the host. Place the
library in that system's PAM module directory and use its absolute path in the local sudo PAM configuration. Keep the
source revision and `Cargo.lock` with the build record so the artifact can be reproduced.

Keep this order:

```text
auth optional /path/to/pam_reattach.so
auth sufficient /path/to/pam_ssh_agent.so strict agent_timeout=30 file=/etc/security/pam-ssh-agent/%u
auth sufficient pam_tid.so
```

Keep Apple's `/etc/pam.d/sudo` unchanged when using its local include mechanism. Keep the existing reattach module
before this module and the Touch ID module after it, so Apple's password fallback remains available. Apply changes
through the host's configuration mechanism instead of replacing managed files by hand.

Keep one sudoers declaration:

```sudoers
Defaults env_keep += "SSH_AUTH_SOCK"
```

Select each trusted public key by its SHA256 fingerprint.
Store selected keys in `/etc/security/pam-ssh-agent/<username>`.
Keep the file root-owned with mode `0600`; keep each parent root-owned,
non-writable by group or other, and free of extended ACLs.
Never copy every agent identity into the trusted file.

Build the package and host configuration before activation. Inspect PAM order, the key fingerprint, file ownership,
and sudoers syntax. Keep a recovery shell available during validation.

## Diagnose

```sh
ssh-add -l
ssh-keygen -lf <public-key-file>
csrutil status
log show --last 5m --style compact --predicate 'eventMessage CONTAINS "pam_ssh_agent"'
```

A key must be both loaded in the current agent and present in the trusted file.
Use `ssh-add <private-key-file>` to load the selected key.
Enter the passphrase in the terminal if required.
Never record the passphrase or private key.

Use `/usr/bin/sudo -k` before every live authentication test.
Do not use `sudo -n` for this test.
Apple sudo skips PAM for noninteractive authentication unless `noninteractive_auth` is enabled.
Confirm module success in the logs; another sufficient PAM module can also succeed.
Test fallback with an absent socket, an untrusted key, and a denied signing request.
Confirm a fresh Touch ID or password authentication after each failure.
The unprivileged PAM tests do not prove Apple's sudo can load the installed module.

Inspect the generated configuration before activation. Confirm the module path is an immutable package path, the strict
option and timeout are present, and the selected key file contains only the fingerprint you approved. Keep the
existing `pam_reattach` line before this module and `pam_tid.so` after it. A successful trusted-key attempt should stop
at the sufficient module; an absent socket, untrusted key, or denied signing request must continue to Apple's Touch ID
and password fallback.

## Roll back

Record the previous host configuration before activation. Use the host's documented rollback or previous-configuration
command, then compare `/etc/pam.d/sudo_local` with the previous version.
Confirm a fresh Touch ID or password authentication.
Restore and activate the desired configuration when rollback validation is complete.

Record the active configuration identifier and the result of `csrutil status` in the deployment record. If profiling is
needed, first capture a non-privileged baseline with the installed Instruments or `xctrace` tools and record the exact
command and output before using it to guide changes.

## Source evidence

Xcode DocumentationSearch did not return the OpenPAM declarations.
The installed headers supply the constants and signatures:
`MacOSX27.0.sdk/usr/include/security/pam_constants.h`, `pam_modules.h`, and `pam_appl.h`.
The installed `pam_authenticate(3)`, `pam_setcred(3)`, and `pam.conf(5)`
manuals define dispatcher flag validation and policy lookup.
The trust loader also uses `MacOSX27.0.sdk/usr/include/sys/fcntl.h` and
`sys/acl.h`, with `man 2 open`, `man 3 acl_get_fd_np`, `man 3 acl_get_entry`,
and `man 3 acl_get_perm_np`. Xcode DocumentationSearch was consulted for
no-follow descriptor opening and ACL access. The selected toolchain is Xcode
27.0 (27A266a), macOS SDK 27.0 (26A425), and Apple Clang 21.0.0.
The developer directory and selected SDK are host-specific. Record their paths and versions with each build.
[Apple XNU `kern_prot.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c)
and [`kern_credential.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_credential.c)
show that `setgroups(0, NULL)` disables the external group resolver and that the following `setgid` sets the only
credential group to the target GID. [Apple `id.c`](https://github.com/apple-oss-distributions/shell_cmds/blob/main/id/id.c)
shows that `id -G` uses `getgrouplist_2` for the current account. The SDK maps modern `getgroups` callers to the
extended symbol. [Apple Libc `getgroups.c`](https://github.com/apple-oss-distributions/Libc/blob/main/sys/getgroups.c)
shows that this symbol also resolves the account group list. The root-only test dynamically resolves the unversioned
`getgroups` symbol when it checks the stored child credential list on macOS.

On 2026-09-22, the 200-sample benchmark reported policy-load p50 12.458 µs, p95 15.5 µs, and p99 24.5 µs. In-process
authentication reported p50 60.292 µs, p95 68.458 µs, and p99 73.25 µs with one identity, and p50 60.667 µs, p95
68.25 µs, and p99 76.417 µs with three decoys followed by the match. These measurements exclude Unix-socket IPC and
hardware-backed user presence.

The Enhanced Security settings were checked with Xcode DocumentationSearch on Xcode 27.2 (27B5019j), macOS SDK 27.2.
The consulted Apple sources were [Enabling enhanced security for your app](https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app),
[Preparing your app to work with pointer authentication](https://developer.apple.com/documentation/security/preparing-your-app-to-work-with-pointer-authentication),
and the Xcode build settings reference. The installed toolchain and SDK are the source of truth for the exact flags
available on a host.
