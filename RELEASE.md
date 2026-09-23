# Release process

Use this checklist for a source release. Distribution packages can add platform-specific steps without making
private builders, accounts, or host paths part of the source tree.

1. Create a release issue and a release branch from the remote default branch.
2. Update the version in `Cargo.toml` and any maintained package metadata. Update the changelog and compatibility
   documentation in the same branch.
3. Confirm that `Cargo.lock` is current. Record the exact Rust compiler, platform toolchain, SDK, target, and feature
   set used for each release artifact.
4. Run the local checks:

   ```sh
   cargo fmt --all -- --check
   cargo clippy --locked --all-targets -- -D warnings
   cargo test --locked --all-targets
   cargo build --locked --release
   cargo package --locked
   ```

5. Review locked dependencies, licenses, vendored-source provenance, exported PAM symbols, linked libraries, and the
   final artifact signature. Record any skipped privileged test as an unverified release claim.
6. For macOS, qualify the artifact against [the support contract](docs/macos-support.md) and the machine-readable
   [release profile](support/macos/release-profile.toml). Record evidence for the selected OS, SDK, target, PAM host,
   trust-file policy, agent socket, fallback behavior, and rollback path. Do not mark the macOS artifact supported from
   build or direct-hook evidence alone.
7. Build each artifact from a clean checkout of the reviewed commit. Keep unsigned payload hashes separate from
   signed package hashes.
8. Review the complete source archive and documentation for private hostnames, user paths, credentials, deployment
   configuration, and account-specific release infrastructure.
9. Merge the reviewed branch, create an annotated version tag, and verify that the tag resolves to the reviewed
   commit. Publish only the artifacts that passed the recorded checks.
10. Publish checksums, dependency and license records, supported-platform limits, known limitations, installation
   instructions, diagnostics, and rollback instructions with the release.

For macOS, also follow `docs/macos.md`. Qualify the installed module through the intended PAM host with SIP enabled.
Treat optional Enhanced Security slices as separate release variants until each slice has runtime evidence on
compatible hardware.
