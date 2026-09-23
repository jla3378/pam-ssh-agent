# pam-bindings 0.3.0

Source: <https://crates.io/crates/pam-bindings/0.3.0>.
Repository: <https://github.com/lvkv/pam-rs>.
Source commit: `d0c1bca3be13030e2a371ecc7b8d801a664e0793`.
Crate checksum: `95ca8ded51d7b55e02c84ee36e024ea9843d800da0ed371e07e6733092bd073e`.
License: MIT. See LICENSE.

The copy includes the library sources, license, README, and Cargo manifest.
The manifest omits upstream example and integration targets that are not included.

The patch selects macOS result codes, flags, message styles, and item identifiers.
Linux definitions remain unchanged.
Exported hooks accept signed C flags. Rust hook methods retain PamFlag.
Argument checks reject null or inconsistent PAM inputs. The panic guard disposes
ordinary payloads inside a second unwind boundary. If a payload destructor also
panics, the guard forgets the secondary payload so no unwind crosses the C ABI.

The macOS `pam_conv(3)` contract leaves failure-path allocations with the
conversation callback. The binding frees and zeroizes successful responses and
does not take ownership after a callback error.

Source gate: Xcode DocumentationSearch did not return OpenPAM declarations.
The installed SDK headers supply the ABI definitions:
`MacOSX27.0.sdk/usr/include/security/pam_constants.h`, `pam_modules.h`, and `pam_appl.h`.
Toolchain: Xcode 27.0 (27A266a), macOS SDK 27.0, arm64-apple-darwin.
