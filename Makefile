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

.PHONY: help check pam install clean

help:
	@echo "Targets:"
	@echo "  check    - cargo fmt --check, cargo clippy --no-deps, cargo test (host arch)"
	@echo "  pam      - build the thin arm64e dylib (needs nightly + build-std)"
	@echo "  install  - build pam, then install into $(PREFIX)/pam_ssh_agent.so (sudo)"
	@echo "  clean    - cargo clean"

check:
	cargo fmt --check
	cargo clippy --no-deps
	cargo test

pam:
	rustup run $(PAM_TOOLCHAIN) cargo build -Z build-std=std --release --target $(TARGET)
	@echo "Built $(DYLIB)"

install: pam
	sudo install -d $(PREFIX)
	sudo install -m 755 $(DYLIB) $(PREFIX)/pam_ssh_agent.so

clean:
	cargo clean
