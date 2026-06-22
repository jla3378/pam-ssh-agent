# Live validation runbook

This module gates `sudo`/`su`. Its automated tests all use mocks — the real PAM FFI boundary
and a live OpenPAM stack are **not** exercised by `cargo test`. This runbook is the procedure to
prove, on a real Mac, that the module both **authenticates** and **fails closed**. Run it once
before trusting the module, and **re-run it after every macOS major upgrade** (the loader and PAM
behavior can change — see the Tahoe note at the bottom).

> [!WARNING]
> Misconfiguring sudo's PAM stack can lock you out of privilege escalation. **Read
> `LOCKOUT-RECOVERY.md` first**, and do not start without the safety setup in §1.

## 1. Safety setup (do this first, every time)

1. **Open a separate terminal and start a persistent root shell — leave it open the whole time:**
   ```sh
   sudo -s        # keep this window open; it is your escape hatch
   ```
   If anything breaks, revert `/etc/pam.d/sudo_local` from this already-root shell (no reboot).
2. Wire the module as **`sufficient`** (never `required`) so a module *failure* falls through to
   the normal Touch ID / password prompt instead of denying you.
3. Keep a tail on the unified log in a third window (this module logs to `AUTHPRIV`):
   ```sh
   log stream --predicate 'eventMessage CONTAINS "pam_ssh_agent"'
   ```

## 2. Prerequisites

- An `ssh-agent` exposing a key, with `SSH_AUTH_SOCK` set in the shell that will run `sudo`
  (e.g. [Secretive](https://github.com/maxgoedjen/secretive) for a Secure Enclave key):
  ```sh
  echo "$SSH_AUTH_SOCK"      # non-empty
  ssh-add -l                 # lists the key you'll authorize
  ```
- The built, **load-verified**, and installed module:
  ```sh
  make pam           # builds + realigns LINKEDIT so dyld will load it (see AUDIT.md)
  make verify-load   # MUST print "dlopen OK" — if it fails, the module won't load into sudo either
  make install       # -> /usr/local/lib/pam/pam_ssh_agent.so
  ```
  > `make verify-load` is the cheap pre-flight that catches a non-loadable build before you
  > touch the PAM stack. Do not wire an un-load-verified module into `sudo`.
- `sudo` must forward the agent socket (it scrubs the environment by default):
  ```sh
  sudo visudo -f /etc/sudoers.d/ssh_agent_env
  # add:  Defaults env_keep += "SSH_AUTH_SOCK"
  ```
- Your agent's public key in `/etc/security/authorized_keys` (that directory exists on macOS):
  ```sh
  ssh-add -L | head -1 | sudo tee -a /etc/security/authorized_keys
  ```
- Wire the module into `/etc/pam.d/sudo_local` (create it from `sudo_local.template` if needed).
  Add the `debug` option **for testing only** so the log shows every decision; remove it for
  production:
  ```
  auth  sufficient  /usr/local/lib/pam/pam_ssh_agent.so  file=/etc/security/authorized_keys debug
  ```
  > Heads-up: if your `sudo_local` has a stale commented line pointing at
  > `/usr/local/lib/libpam_ssh_agent.dylib`, delete it — the correct install path is
  > `/usr/local/lib/pam/pam_ssh_agent.so`.

After each change below, reset the sudo timestamp before testing: `sudo -k`.

## 3. What you'll see in the log

At the default level the module logs an info banner at the start of every attempt
(`src/lib.rs:144`):

```
pam_ssh_agent(sudo:auth): pam-ssh-agent 0.10.2 authenticating user '<you>' using ssh-agent at '<sock>'
```

With the `debug` option set, you'll also see the outcome line — `Successful call to
pam_sm_authenticate(), returning PAM_SUCCESS` on success, or `error: Agent did not know of any of
the allowed keys` (and `Failed call …, returning PAM_AUTH_ERR`) on a deny. **Behaviorally:**
a success means `sudo` runs *without* a prompt; a deny means `sudo` falls through to the normal
Touch ID / password prompt (because the module is `sufficient`).

## 4. Test matrix — positives first, then the deny paths

Run in order. ✅ = expected pass (auth without prompt). 🔒 = expected **fail-closed** (falls
through to the password/Touch ID prompt — never a lockout, never a silent success).

| # | Case | Action | Expected | Code ref |
|---|------|--------|----------|----------|
| 1 | ✅ Trusted key | trusted key in agent + in `authorized_keys`; `sudo -k; sudo true` | succeeds, **no** prompt; banner + `PAM_SUCCESS` in log | `src/lib.rs:171` |
| 2 | 🔒 Untrusted key | remove the key from `authorized_keys` (or load a different key); `sudo -k; sudo true` | falls through to prompt; `Agent did not know of any of the allowed keys` | `src/lib.rs:173` |
| 3 | 🔒 No agent | `unset SSH_AUTH_SOCK` in the test shell; `sudo -k; sudo true` | falls through; `SSH_AUTH_SOCK not set …` error | `src/lib.rs:259` |
| 4 | 🔒 Stale socket | `export SSH_AUTH_SOCK=/tmp/nope; sudo -k; sudo true` | falls through; connect error | `src/lib.rs:153` |
| 5 | 🔒 Empty agent | `ssh-add -D` (remove all keys); `sudo -k; sudo true` | falls through; no matching key | `src/auth.rs:47` |
| 6 | 🔒 Missing keys file | point the PAM line at `file=/etc/security/authorized_keys_nope`; `sudo -k; sudo true` | falls through; `No valid keys … does not exist` | `src/filter.rs:42` |
| 7 | ✅ Malformed line is non-fatal | prepend a junk line above a valid key in `authorized_keys`; `sudo -k; sudo true` | still succeeds via the valid line; `Failed to parse line …` logged but not fatal | `src/filter.rs:138` |
| 8 | ✅ Try-next-key | authorize an `sk`/hardware key **and** a software key, with the hardware key **unplugged**; `sudo -k; sudo true` | succeeds via the software key (needs `debug` to see `RemoteFailure; trying next key`) | `src/auth.rs:34` |

> Restore `authorized_keys`, `SSH_AUTH_SOCK`, and the PAM line to the working state from #1
> between cases.

## 5. Certificate cases (if you use cert auth)

Mint a **far-future-expiry** user cert (a genuine no-expiry cert is rejected by `ssh-key` — see
the cert note in `README.md`), configure a `cert-authority` line or `ca_keys_file=`, ensure
`PAM_USER` is in the cert principals, then:

- ✅ valid cert in window → succeeds.
- 🔒 wrong principal → `Cert matches but '<u>' is not in the list of valid principals` (`src/auth.rs:84`).
- 🔒 expired cert → `Certificate validation failed` (`src/auth.rs:74`).
- 🔒 host cert → `Cert type is not user …` (`src/auth.rs:79`).

## 6. Confirm the signing prerequisite (does ad-hoc load into sudo?)

Do case #1 with the **ad-hoc** `make pam` dylib (no `make sign`). It is expected to load and
succeed: `sudo` carries `com.apple.private.security.clear-library-validation`, so PAM retries with
library validation disabled. Confirm:

```sh
codesign -d --entitlements - "$(which sudo)" 2>/dev/null | grep -i clear-library-validation
```

You may see a benign `Library Validation failed: Rejecting …` line in the log even though auth
**succeeds** — that's the retry, not a failure. If case #1 succeeds ad-hoc, then Developer ID
signing/notarization (`make sign`/`make notarize`) is defense-in-depth, **not** a load
requirement — record that conclusion in `AUDIT.md`.

## 7. sshd determination (likely unsupported on macOS 26+/Tahoe)

On Tahoe, `sshd-session` is a *platform binary* that may refuse to map a non-platform module
("mapping process is a platform binary, but mapped file is not"), and Developer ID signing cannot
change that. Test only on a **throwaway** sshd (never your primary Remote Login config), with the
held root shell open. If the log shows the platform-binary rejection for `sshd`/`sshd-session`,
the module does not load there → **scope this module to `sudo`/`su`** and narrow the README's sshd
sections. If it *does* load, confirm the `SSH_AUTH_INFO_0` shortcut stays inert and auth falls
through to challenge-response (`src/lib.rs:187`).

## 8. Record results & clean up

- Record per-row pass/fail with the date, macOS version (`sw_vers`), and agent used. Update
  `AUDIT.md` (the `Not exercised` / `Remaining (user, on a Mac)` items) once §4 passes.
- **Remove the `debug` option** from the production `sudo_local` line.
- To back out entirely: `make uninstall` and revert the PAM config (see `LOCKOUT-RECOVERY.md`).

> [!NOTE]
> **Re-run this runbook after every macOS major upgrade.** Library-validation and platform-binary
> rules have changed between releases (the Tahoe `sshd` regression is the precedent), and
> `/etc/pam.d/sudo` is Apple-managed and reset on updates (only `sudo_local` survives).
