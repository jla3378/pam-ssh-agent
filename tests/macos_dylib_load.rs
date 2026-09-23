#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[test]
#[ignore = "requires a built release dylib in PAM_LOADER_MODULE"]
fn release_dylib_is_accepted_by_dyld() {
    let path = PathBuf::from(std::env::var_os("PAM_LOADER_MODULE").expect("PAM_LOADER_MODULE"));
    assert!(path.is_absolute(), "module path must be absolute");
    assert!(
        path.is_file(),
        "module path is not a file: {}",
        path.display()
    );
    let path = CString::new(path.as_os_str().as_bytes()).expect("module path contains NUL");

    unsafe {
        let handle = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let error = libc::dlerror();
            let detail = if error.is_null() {
                "unknown dyld error".to_owned()
            } else {
                CStr::from_ptr(error).to_string_lossy().into_owned()
            };
            panic!("dyld rejected PAM module: {detail}");
        }
        assert_eq!(libc::dlclose(handle), 0, "dlclose failed");
    }
}
