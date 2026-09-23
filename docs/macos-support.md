# macOS production support contract

This document defines the first supported macOS profile for `pam-ssh-agent`.
It is a selected contract. It is not a claim that every item has passed live
qualification.

## Selected profile

The profile targets the selected Apple host used for qualification:

| Property | Contract |
| --- | --- |
| Host OS | macOS 27.0, build 26A428 |
| Hardware | Mac16,8 with Apple M4 Pro |
| Architecture | arm64, minimum macOS 27.0 |
| PAM host | Apple `/usr/bin/sudo` through the `sudo` PAM service |
| Invocation | Non-root local account, default root target |
| SIP | Enabled |
| Crypto | Default Rust crypto implementation |
| PAM mode | `strict` |
| Module position | `sufficient`, before the existing Touch ID module |
| Agent | Apple `/usr/bin/ssh-agent` software agent |
| Agent socket | The `SSH_AUTH_SOCK` value in the PAM environment |
| Agent fallback | None. `default_ssh_auth_sock` is excluded |
| Request deadline | 30 seconds for the complete agent request |
| Trusted key | Exactly one root-controlled bare Ed25519 public key per account |
| Trust path | `file=/etc/security/pam-ssh-agent/%u` |
| User presence | No fresh user-presence claim |

The deployed PAM line has this shape. The package supplies the absolute module
path:

```text
auth sufficient /absolute/package/path/lib/security/pam_ssh_agent.so strict agent_timeout=30 file=/etc/security/pam-ssh-agent/%u
```

The existing reattach module, when present, stays before this line. The
existing Apple Touch ID module stays after it. A failure in this module must
continue to Apple's Touch ID and password fallback.

The trusted file contains one selected public key in bare OpenSSH format. The
key is selected by its SHA256 fingerprint before activation. The module does
not authorize every identity in the agent. The agent must hold the matching
private key and complete the signing request. The release configuration must
set the file owner to root and mode to `0600`. Each parent must be root-owned
and writable only by its owner.

The profile uses the current `SSH_AUTH_SOCK` only. The socket is a transport
endpoint, not the trust decision: the module verifies the returned signature
against the selected key. Qualification must still record the socket owner,
permissions, and agent implementation.

## Selected build

The stable build uses Rust 1.96.1 for `aarch64-apple-darwin`. It clears
ambient deployment and Rust flag variables, applies the macOS 27.0 minimum
only to target code, and gives the library a path-independent install name:

`Cargo.toml` keeps Rust 1.88 as the source compatibility floor. That value is
not the release compiler. Qualification uses the exact Rust 1.96.1 toolchain.

```sh
release_rustc=$(rustup which --toolchain 1.96.1-aarch64-apple-darwin rustc)
env -u MACOSX_DEPLOYMENT_TARGET \
  -u RUSTFLAGS \
  -u CARGO_ENCODED_RUSTFLAGS \
  -u CARGO_BUILD_RUSTFLAGS \
  -u CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS \
  -u RUSTC_WRAPPER \
  -u RUSTC_WORKSPACE_WRAPPER \
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk \
  CARGO_TARGET_DIR=target/macos-27 \
  RUSTC="$release_rustc" \
  rustup run 1.96.1-aarch64-apple-darwin \
  cargo build --locked --release --no-default-features \
    --target aarch64-apple-darwin \
    --config 'target.aarch64-apple-darwin.rustflags=["-C","link-arg=-mmacosx-version-min=27.0","-C","link-arg=-Wl,-install_name,pam_ssh_agent.so"]'
```

Do not set `MACOSX_DEPLOYMENT_TARGET` for the complete Cargo process. That
setting also changes host procedural macros and prevents Rust 1.96.1 from
loading `thiserror_impl` on this host. The target-specific setting produces a
macOS 27.0 module while host procedural macros keep their compatible minimum.
The `RUSTC` assignment is required because another Rust installation can
precede the rustup shims in `PATH`. The release record must verify the Rust,
Xcode, and SDK build identifiers before it accepts this command's output.

Cargo emits `libpam_ssh_agent.dylib`. Packaging installs those bytes as
`pam_ssh_agent.so` at the absolute path used by PAM. Inspect and sign the final
installed filename as a separate release step.

## Account and PAM rules

`%u` is the PAM `PAM_USER` value. Strict mode accepts a plain local account
name and resolves it to the same local account. It rejects path-like names,
aliases, unknown accounts, and names that do not match the local resolver.

The profile requires a non-root local invoker, the `sudo` PAM service, and
sudo's default root target. Live qualification must confirm that Apple sudo
sets `PAM_USER` to that invoker. Root invokers, alternate sudo targets, and
other PAM callers are outside this profile until separately tested.

If an account is renamed, move or re-enroll its trust file. If an account is
deleted, remove its trust file. A later account with the same name can inherit
an old trust file if the file is left behind. Treat this as a deployment
failure and remove the orphan before re-enrollment.

## Failure and fallback behavior

Authentication succeeds only after the agent signs a challenge and the module
verifies the signature with the selected trusted key. These cases fail this
module and must reach fallback:

- `SSH_AUTH_SOCK` is absent, invalid, unavailable, or times out.
- The agent does not hold the selected key.
- The agent denies, refuses, or returns an invalid signature.
- The trust file is missing, malformed, changed, or not root-controlled.
- PAM items or user validation fail.

A trust file with more than the selected key or a mode other than `0600` is
outside this contract even though the implementation can accept a broader
configuration. The release inspection must reject that configuration.

The module reports authentication failure to PAM. It does not grant a
credential in `pam_sm_setcred`; the PAM host continues its configured stack.
The module does not claim that a signature proves a physical presence event,
Touch ID event, Secure Enclave use, or hardware-backed key use.

## Excluded profiles

The following profiles are outside this contract:

- legacy mode and the `sshd` environment shortcut;
- `default_ssh_auth_sock` and any alternate socket path;
- helper commands, certificate authorities, authorized-keys options, and
  security-key policy;
- RSA, ECDSA, security-key, and certificate trust entries;
- forwarded-agent qualification;
- SSH agent products other than Apple `/usr/bin/ssh-agent`;
- arm64e, arm64e.x1, pointer authentication, checked pointer arithmetic, and
  Enhanced Security runtime claims;
- PAM hosts other than Apple `sudo`, root invokers, alternate sudo targets,
  and non-local invokers;
- GUI login, screen unlock, and remote SSH acceptance;
- public binary packaging and notarization, which have separate release gates.

RSA has no minimum key size in this profile because RSA is excluded. Other
arm64 hardware can use the build only after separate runtime qualification.

## Evidence vocabulary

Use one status for every matrix row:

| Status | Meaning |
| --- | --- |
| specified | Required by this contract; no execution evidence yet |
| verified | Checked by a deterministic inspection or build check |
| reproduced | Repeated from the recorded source and toolchain |
| historical | Evidence from an earlier revision or host |
| unverified | Relevant evidence is missing |
| unsupported | Outside this contract |
| blocked | The check cannot run until a named dependency or approval is available |
| not-applicable | The row does not apply to this profile |

Record the evidence type with the status. Allowed types are `build`,
`inspection`, `direct-hook`, `dynamic-loader`, `sudo`, `fallback`,
`fault`, and `performance`.

## Compatibility and evidence matrix

| Area | Contract requirement | Initial status | Evidence type |
| --- | --- | --- | --- |
| OS and SIP | macOS 27.0 build 26A428 on Mac16,8, SIP enabled | verified | inspection |
| Toolchain | Xcode 27.0, SDK 27.0, pinned Rust 1.96.1 | verified | build |
| Artifact | arm64 dynamic library, minimum OS 27.0, stable install name | verified | build, inspection |
| PAM boundary | macOS constants, exported entry points, and real PAM handles | verified | direct-hook |
| Loader | Apple sudo loads the absolute module path | unverified | dynamic-loader |
| Trust file | One root-controlled bare Ed25519 key at `%u` path | specified | inspection |
| Agent | Apple `/usr/bin/ssh-agent` at current `SSH_AUTH_SOCK` | unverified | sudo |
| Success | Fresh trusted-key sudo authentication succeeds | unverified | sudo |
| Fallback | Absent socket, untrusted key, and denied signature reach Touch ID/password | unverified | fallback, fault |
| Failure bounds | Agent request completes within 30 seconds | verified in direct tests; live fault check pending | fault |
| Performance | Record socket round-trip and module overhead | unverified | performance |
| Rollback | Restore the previous host configuration and authenticate | unverified | sudo, fallback |
| Enhanced Security slices | No claim in this profile | unsupported | inspection |

The profile stays `selected-not-qualified` until every required baseline row
has `verified` or `reproduced` evidence for one release candidate. A release
also fails qualification while an authentication-bypass, lockout, hang,
resource-exhaustion, or release-integrity blocker is open.

## Release record

Each qualified artifact record must include:

- reviewed source commit and version;
- `Cargo.lock` digest and dependency/license record;
- Rust compiler, Cargo, target triple, profile, feature set, and build
  command;
- Xcode, SDK, Clang, macOS, architecture, and deployment target;
- artifact SHA256, Mach-O architecture/minimum OS, exported symbols, linked
  libraries, and code-signing result;
- PAM module path and complete module arguments;
- trusted key SHA256 fingerprint and trust-file ownership/mode;
- agent path, socket ownership/mode, and test identity;
- PAM order and sudoers environment preservation;
- results for success, absent socket, untrusted key, denied signature,
  fallback, rollback, and timing checks;
- SIP status, timestamp, host class, and operator-independent test output;
- known gaps, skipped privileged checks, and the next qualification action.

## Apple source gate and toolchain

The source gate consulted Apple's
[Enhanced Security](https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app),
[pointer authentication](https://developer.apple.com/documentation/security/preparing-your-app-to-work-with-pointer-authentication),
and [notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
documentation. [Apple Developer Technical Support](https://developer.apple.com/forums/thread/729622?answerId=752854022#752854022)
states that sudo can load a third-party PAM module, but that statement does not
replace live loader evidence.

The installed SDK headers supplied the OpenPAM declarations and constants
because Xcode DocumentationSearch did not return those declarations. The
headers are `security/pam_constants.h`, `security/pam_modules.h`, and
`security/pam_appl.h` in the macOS 27.0 SDK.

The selected stable toolchain is Xcode 27.0 (27A266a), macOS SDK 27.0
(26A425), Apple Clang 21.0.0 (clang-2100.3.34.2), Rust 1.96.1
(`31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd`), and Cargo 1.96.1
(`356927216`). The dated nightly reference for excluded Enhanced Security
slices is `nightly-2026-06-10`, Rust 1.98.0-nightly
(`beae781308e9ddef13074a03faf57ca2fac59a5b`).

This contract does not claim that Apple sudo dynamically loads the module, or
that the live PAM stack succeeds, until the dynamic-loader and sudo evidence
rows pass on the selected host.
