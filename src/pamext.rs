use crate::openpam::PamHandle;
use anyhow::Result;

/// Extension trait over the PAM handle providing the two items this module needs.
/// It is a trait so tests can inject fakes (see `CannedHandler`/`DummyHandle` in
/// `src/test.rs`) instead of a real `PamHandle`.
pub trait PamHandleExt {
    /// Fetch the authenticating user (PAM_USER).
    fn get_calling_user(&self) -> Result<String>;

    /// Fetch the calling service name (PAM_SERVICE), i.e. the program using PAM.
    fn get_service(&self) -> Result<String>;
}

impl PamHandleExt for PamHandle {
    fn get_calling_user(&self) -> Result<String> {
        self.user()
    }

    fn get_service(&self) -> Result<String> {
        self.service()
    }
}
