#[cfg(not(target_os = "macos"))]
#[path = "linux_constants.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos_constants.rs"]
mod platform;

pub use platform::*;
