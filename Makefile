# Makefile for pam-ssh-agent (macOS, arm64e-only).
#
# The shippable PAM module is a THIN arm64e Mach-O dylib. arm64e-apple-darwin
# is a tier-3 Rust target with no prebuilt std, so building it requires a
# nightly toolchain plus -Z build-std=std to compile the standard library from
# source. Correctness checks (`make check`) run on the host toolchain/arch,
# since the crypto and PAM logic is architecture-independent.

PAM_TOOLCHAIN ?= nightly
TARGET := arm64e-apple-darwin
DYLIB := target/$(TARGET)/release/libpam_ssh_agent.dylib
PREFIX ?= /usr/local/lib/pam

# Signing / notarization are LOCAL-ONLY (need your Developer ID identity + an Apple notary
# credential profile; never in CI). SIGN_IDENTITY is a prefix match against your keychain;
# override with the full "Developer ID Application: Name (TEAMID)" string if ambiguous.
# Set up the notary profile once (not committed):
#   xcrun notarytool store-credentials $(NOTARY_PROFILE) --apple-id <id> --team-id <team> --password <app-specific-pw>
SIGN_IDENTITY ?= Developer ID Application
NOTARY_PROFILE ?= pam-ssh-agent-notary
NOTARIZE_ZIP := target/pam_ssh_agent-notarize.zip

.PHONY: help check pam install uninstall sign notarize verify-artifact clean

help:
	@echo "Targets:"
	@echo "  check     - cargo fmt --check, cargo clippy --no-deps, cargo test (host arch)"
	@echo "  pam       - build the thin arm64e dylib (needs nightly + build-std)"
	@echo "  install   - build pam, then install into $(PREFIX)/pam_ssh_agent.so (sudo)"
	@echo "  uninstall - remove $(PREFIX)/pam_ssh_agent.so (sudo); does NOT touch /etc/pam.d"
	@echo "  sign      - build pam, then Developer ID sign (hardened runtime + timestamp)"
	@echo "  notarize  - sign, then zip + submit to Apple notary (bare dylib is NOT stapled)"
	@echo "  verify-artifact - inspect a built dylib: arch, exports, signature"
	@echo "  clean     - cargo clean"

check:
	cargo fmt --check
	cargo clippy --no-deps
	cargo test

# Homebrew's stable rustc/cargo shadow rustup's in PATH, so a bare `rustup run` ends up
# invoking the stable rustc (which rejects -Z). Pin both cargo and rustc to the nightly
# toolchain explicitly.
pam:
	RUSTC="$$(rustup which --toolchain $(PAM_TOOLCHAIN) rustc)" \
		"$$(rustup which --toolchain $(PAM_TOOLCHAIN) cargo)" \
		build -Z build-std=std --release --target $(TARGET)
	@echo "Built $(DYLIB)"

install: pam
	sudo install -d $(PREFIX)
	sudo install -m 755 $(DYLIB) $(PREFIX)/pam_ssh_agent.so

# Removes only the installed module. Reverting the PAM wiring is intentionally NOT
# automated (it touches privileged config you edited by hand) — see the notes below
# and LOCKOUT-RECOVERY.md.
uninstall:
	sudo rm -f $(PREFIX)/pam_ssh_agent.so
	@echo "Removed $(PREFIX)/pam_ssh_agent.so."
	@echo "This does NOT revert your PAM config. To fully back out, also:"
	@echo "  - remove the pam_ssh_agent line from /etc/pam.d/sudo_local (and any test service)"
	@echo "  - optionally remove /etc/sudoers.d/ssh_agent_env"
	@echo "  - optionally clean entries from /etc/security/authorized_keys"

sign: pam
	codesign --force --sign "$(SIGN_IDENTITY)" --options runtime --timestamp $(DYLIB)
	@echo "Signed $(DYLIB). Verifying:"
	codesign --verify --strict --verbose=4 $(DYLIB)
	@codesign -dvvv $(DYLIB) 2>&1 | grep -E 'Authority|TeamIdentifier|Timestamp|flags=' || true

# A bare .dylib CANNOT be stapled (no bundle to hold the ticket), so we zip + submit and
# rely on the online notarization record. notarytool requires a container, hence the zip.
notarize: sign
	/usr/bin/ditto -c -k --keepParent $(DYLIB) $(NOTARIZE_ZIP)
	xcrun notarytool submit $(NOTARIZE_ZIP) --keychain-profile $(NOTARY_PROFILE) --wait
	@echo "Notarized. A standalone dylib is intentionally NOT stapled (see README)."
	@echo "On failure inspect: xcrun notarytool log <submission-id> --keychain-profile $(NOTARY_PROFILE)"

# Inspect an already-built dylib (run after sign/notarize, before install).
verify-artifact:
	@echo "== file (expect: thin Mach-O arm64e, not fat) =="; file $(DYLIB)
	@echo "== exported PAM entry points =="; nm -gU $(DYLIB) | grep -E 'pam_sm_(authenticate|setcred)'
	@echo "== linked libraries =="; otool -L $(DYLIB)
	@echo "== signature =="; codesign --verify --strict --verbose=4 $(DYLIB)
	@codesign -dvvv $(DYLIB) 2>&1 | grep -E 'Authority|TeamIdentifier|Timestamp|flags=' || true
	@echo "Note: 'spctl -a -t install' rejecting this dylib is expected and benign — sudo/su"
	@echo "dlopen() the module and Gatekeeper does not gate that path; 'stapler validate' is N/A."

clean:
	cargo clean
