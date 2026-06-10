//! Minimal OpenPAM FFI for this macOS-only module.
//!
//! This replaces the `pam-bindings` crate, which hardcodes **Linux-PAM** numbering.
//! The constants below mirror macOS's `<security/pam_constants.h>` (verified against the
//! Xcode SDK on macOS 26). The distinction is load-bearing: OpenPAM numbers result codes
//! differently from Linux-PAM — `PAM_AUTH_ERR` is **9** here but **7** on Linux-PAM — so
//! returning the Linux value would make a denial read as `PAM_PERM_DENIED` to the PAM host.
//! Only `PAM_SUCCESS` (0) agrees across both implementations.

use anyhow::{Result, anyhow};
use std::ffi::{CStr, c_char, c_int, c_void};

// Result codes — security/pam_constants.h
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 9;

// Item types — security/pam_constants.h
const PAM_SERVICE: c_int = 1;
// PAM_USER (2) is read via pam_get_user(), not pam_get_item().

/// Opaque OpenPAM handle. We only ever hold it behind a pointer supplied by libpam and
/// pass it back; the real layout is private to libpam.
#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

#[link(name = "pam")]
unsafe extern "C" {
    // `pamh` is declared `*const` for convenience; libpam takes ownership of its own
    // internal state behind the pointer, and our `PamHandle` is a zero-sized opaque
    // stand-in, so there is nothing on the Rust side to alias.
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_get_user(
        pamh: *const PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

impl PamHandle {
    /// The authenticating user. Uses `pam_get_user`, which returns an already-set
    /// PAM_USER or, if the host left it unset, obtains it through the PAM conversation.
    pub fn user(&self) -> Result<String> {
        let mut out: *const c_char = std::ptr::null();
        // SAFETY: `self` is a live pamh for the duration of the PAM call; `out` receives a
        // pointer owned by libpam that remains valid until the next PAM call.
        let rc = unsafe { pam_get_user(self, &mut out, std::ptr::null()) };
        if rc != PAM_SUCCESS {
            return Err(anyhow!("pam_get_user failed (rc={rc})"));
        }
        owned_string(out, "PAM_USER")
    }

    /// The PAM service name (e.g. "sudo", "sshd", "su").
    pub fn service(&self) -> Result<String> {
        let mut out: *const c_void = std::ptr::null();
        // SAFETY: as above; PAM_SERVICE yields a `const char *`.
        let rc = unsafe { pam_get_item(self, PAM_SERVICE, &mut out) };
        if rc != PAM_SUCCESS {
            return Err(anyhow!("pam_get_item(PAM_SERVICE) failed (rc={rc})"));
        }
        owned_string(out as *const c_char, "PAM_SERVICE")
    }
}

/// Copy a libpam-owned C string into an owned `String`.
fn owned_string(ptr: *const c_char, what: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(anyhow!("{what} is null"));
    }
    // SAFETY: `ptr` is non-null and points to a NUL-terminated string owned by libpam.
    let value = unsafe { CStr::from_ptr(ptr) };
    Ok(value
        .to_str()
        .map_err(|e| anyhow!("{what} is not valid UTF-8: {e}"))?
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::{PAM_AUTH_ERR, PAM_SERVICE, PAM_SUCCESS};

    // Guards against a silent edit to the OpenPAM constants. See the module docs: these
    // differ from Linux-PAM, where PAM_AUTH_ERR is 7.
    #[test]
    fn openpam_constant_values() {
        assert_eq!(PAM_SUCCESS, 0);
        assert_eq!(PAM_AUTH_ERR, 9);
        assert_eq!(PAM_SERVICE, 1);
    }
}
