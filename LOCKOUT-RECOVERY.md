# Recovering from a sudo lockout

Misconfiguring sudo's PAM stack can lock you out of privilege escalation. This module is
loaded by `sudo`/`su` via PAM, so a bad `/etc/pam.d/sudo_local` (wrong control flag, a
`required`/`auth` line that errors, a path to a module that won't load) can leave you unable
to `sudo`. On Apple Silicon there is **no single-user mode** (no `Cmd-S`, no NVRAM boot), so
recovery is genuinely different from Intel. Read this **before** doing live validation.

The fix in every case is the same: **remove the module's line from `/etc/pam.d/sudo_local`**
(or delete that file entirely — Apple's `sudo_local.template` ships all-commented, and
`/etc/pam.d/sudo`'s `auth include sudo_local` simply skips a missing include).

## 0. First line of defense — the held root shell (do this every time)

Before you touch `sudo_local`, open a **separate** terminal window and start a persistent
root shell, and leave it open for the whole session:

```sh
sudo -s        # or: sudo -i
```

If `sudo` then breaks, fix it from that already-root shell — no reboot needed:

```sh
# inspect, then revert
cat /etc/pam.d/sudo_local
rm /etc/pam.d/sudo_local          # safe: removes the whole local include
# (or edit it to delete just the pam_ssh_agent line)
```

Also wire the module as `sufficient` (not `required`) while testing, so a module *failure*
falls through to the normal password prompt instead of denying.

## 1. If you have no root shell — boot to recoveryOS (Apple Silicon)

1. **Shut down** the Mac completely (Apple menu → Shut Down).
2. Press and **hold the power button** until you see **"Loading startup options"**.
3. Click **Options**, then **Continue** to enter recoveryOS. Authenticate as an admin user if
   prompted.
4. In the menu bar choose **Utilities → Terminal**.

### 1a. Mount the Data volume (FileVault-aware)

recoveryOS does not always auto-mount your data volume. The simplest, FileVault-correct way:

- Open **Utilities → Disk Utility**, select your **"Macintosh HD - Data"** volume (the name may
  differ — it is the `… - Data` APFS volume), and click **Mount**. If FileVault is on, you'll
  be prompted for a login password or your recovery key. Then quit Disk Utility and reopen
  **Terminal**.

Confirm it's mounted and find its path:

```sh
ls /Volumes
```

You should see something like `/Volumes/Macintosh HD - Data`. (If it isn't there, in Terminal
you can unlock + mount with `diskutil apfs listVolumes` to find the Data volume, then
`diskutil apfs unlockVolume <volume> ` and `diskutil mount <volume>`.)

### 1b. Remove the offending PAM config

`/etc` is a symlink to `/private/etc`, so on the mounted Data volume the file lives under
`private/etc`. Using the example volume name:

```sh
DATA="/Volumes/Macintosh HD - Data"
ls -l "$DATA/private/etc/pam.d/sudo_local"      # confirm it's there
rm "$DATA/private/etc/pam.d/sudo_local"          # remove the whole local include
```

Removing `sudo_local` entirely is the safe, blunt fix. If you'd rather keep the file and
delete only the module's line, edit it instead:

```sh
nano "$DATA/private/etc/pam.d/sudo_local"        # delete the pam_ssh_agent.so line, save
```

### 1c. Reboot

Apple menu → **Restart**. `sudo` is back to its default (password) behavior.

## 2. Notes & gotchas

- **Removing the module file alone may not be enough.** Deleting
  `/usr/local/lib/pam/pam_ssh_agent.so` (e.g. `make uninstall`) does not help if `sudo_local`
  still references it: with `sufficient` a missing module errors and falls through (you're
  fine), but a `required`/misordered line could still block. The reliable fix is removing the
  `sudo_local` line, as above.
- **Volume name varies.** "Macintosh HD" is the default; yours may differ. Use `ls /Volumes`.
- **FileVault.** If enabled, you cannot read the Data volume in recoveryOS without unlocking it
  (login password or the recovery key generated when FileVault was turned on). Keep that key
  somewhere you can reach it from another device.
- **Prefer the held root shell.** recoveryOS recovery is slow and FileVault-gated; the open
  root shell in §0 turns a lockout into a one-line revert. Never run live validation without
  one.

See also `README.md` → "Wiring it into sudo" (lockout-safety warning) and the `make uninstall`
target for backing the module out cleanly.
