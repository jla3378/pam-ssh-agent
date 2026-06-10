---
name: release
description: Bump the pam-ssh-agent version in Cargo.toml and tag the release. Use when cutting a new release.
disable-model-invocation: true
---

# release

This is a macOS-only module; there is no Debian packaging. The version lives in a single
place. When the user asks to release version `X.Y.Z`:

1. **`Cargo.toml`** — set `version = "X.Y.Z"` in `[package]`.

Procedure:
- If the version wasn't given, ask for it. Read the current version from `Cargo.toml` and
  show the bump (old → new) before editing.
- Apply the edit, then run `cargo build` so `Cargo.lock` picks up the new version.
- Show `git diff --stat`. This does **not** commit or push — remind the user.
- Tagging: once `vX.Y.Z` is committed, the release is tagged `git tag vX.Y.Z` (and pushed
  with `git push --tags`). Do not tag, commit, or push unless the user asks.
