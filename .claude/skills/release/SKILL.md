---
name: release
description: Bump the pam-ssh-agent version consistently across the three files where it is hard-coded (Cargo.toml, create-deb-dsc.sh, debian/changelog) and add a changelog entry. Use when cutting a new release.
disable-model-invocation: true
---

# release

The version string is duplicated in **three files that must stay in sync**. When the user
asks to release version `X.Y.Z`:

1. **`Cargo.toml`** — set `version = "X.Y.Z"` in `[package]`.
2. **`create-deb-dsc.sh`** — set `VERSION=X.Y.Z`.
3. **`debian/changelog`** — prepend a new top entry, matching the existing entry's
   distribution and maintainer unless told otherwise:
   ```
   pam-ssh-agent (X.Y.Z-1~<dist>) <dist>; urgency=medium

     * <summary of changes>

    -- <Maintainer Name> <email>  <RFC 2822 date>
   ```

Procedure:
- If the version wasn't given, ask for it. Read the current version from `Cargo.toml` and
  show the bump (old → new) before editing.
- Do **not** invent the changelog summary — ask the user, or derive candidate bullets from
  `git log <last-tag>..HEAD` (or since the previous changelog entry) and confirm them.
- Apply all three edits, then run `cargo build` so `Cargo.lock` picks up the new version.
- Show `git diff --stat` and remind the user this does **not** tag, commit, or push.
