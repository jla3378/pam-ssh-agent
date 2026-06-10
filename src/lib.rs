// This is a macOS-only fork: it targets OpenPAM and is built as an arm64e PAM module.
#[cfg(not(target_os = "macos"))]
compile_error!("pam-ssh-agent (this fork) is macOS-only");

mod agent;
mod args;
mod auth;
mod cmd;
mod environment;
mod expansions;
pub mod filter;
mod logging;
mod openpam;
mod pamext;
#[cfg(test)]
mod test;
mod verify;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use crate::auth::validate_cert;
use crate::openpam::{PAM_AUTH_ERR, PAM_SUCCESS, PamHandle};
use std::env;
use std::env::VarError;

use crate::environment::{Environment, UnixEnvironment};
use crate::filter::IdentityFilter;
use crate::logging::init_logging;
use crate::pamext::PamHandleExt;
use anyhow::{Result, anyhow};
use args::Args;
use log::{debug, error, info};
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::{Certificate, PublicKey};
use std::ffi::{CStr, c_char, c_int};
use std::path::Path;
use std::time::SystemTime;

/// PAM authentication entry point (called by libpam). Returns `PAM_SUCCESS` if the
/// ssh-agent reachable through `SSH_AUTH_SOCK` signs a random challenge with a private key
/// whose public key is trusted by this module's configuration, otherwise `PAM_AUTH_ERR`.
/// See README.md for how the arguments select authorized keys and CA keys. Diagnostics go
/// to the AUTHPRIV syslog facility.
///
/// # Safety
/// libpam calls this with a valid `pamh` and an `argv` of `argc` NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // A Rust panic must never unwind across the C boundary into the PAM host (UB).
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: libpam passes a valid handle; null is defended against regardless.
        let Some(handle) = (unsafe { pamh.as_ref() }) else {
            error!("pam_sm_authenticate called with a null PAM handle");
            return PAM_AUTH_ERR;
        };
        // SAFETY: argv holds argc entries per the C contract; collect_args bounds-checks.
        let args = unsafe { collect_args(argc, argv) };
        match run(args, handle) {
            Ok(()) => {
                debug!("Successful call to pam_sm_authenticate(), returning PAM_SUCCESS");
                PAM_SUCCESS
            }
            Err(err) => {
                for line in format!("{err:?}").split('\n') {
                    error!("{line}");
                }
                debug!("Failed call to pam_sm_authenticate(), returning PAM_AUTH_ERR");
                PAM_AUTH_ERR
            }
        }
    }))
    .unwrap_or(PAM_AUTH_ERR)
}

/// `doas`/`sudo` call `pam_setcred()`; it must succeed or they error out. This module has
/// no credentials to (re)establish, so it is a deliberate no-op.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// Convert libpam's `(argc, argv)` into borrowed `CStr`s, skipping null entries. Returns
/// empty if `argv` is null or `argc <= 0`.
///
/// The borrows are tied to libpam's argv, which is only valid for the duration of this PAM
/// call; the lifetime `'a` is unconstrained, so callers MUST consume them before returning
/// control to libpam. `run` → `Args::parse` does exactly that — it copies every argument
/// into owned `String`s, and the `Vec` is dropped before `pam_sm_authenticate` returns.
///
/// # Safety
/// `argv` must point to at least `argc` pointers, each either null or a valid
/// NUL-terminated C string that outlives the returned borrows.
unsafe fn collect_args<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a CStr> {
    if argv.is_null() || argc <= 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(argc as usize);
    for i in 0..argc as isize {
        // SAFETY: the caller guarantees argv has at least argc entries.
        let p = unsafe { *argv.offset(i) };
        if !p.is_null() {
            // SAFETY: the caller guarantees each non-null entry is a valid C string.
            out.push(unsafe { CStr::from_ptr(p) });
        }
    }
    out
}

fn run(args: Vec<&CStr>, pam_handle: &PamHandle) -> Result<()> {
    // A logging-setup failure must never deny authentication: on some platforms (e.g.
    // macOS) the syslog socket probed by init_logging() may be unavailable, and
    // propagating that error would fail every authentication closed. Best-effort instead.
    if let Err(e) = init_logging(pam_handle.get_service().unwrap_or("unknown".into())) {
        eprintln!("pam_ssh_agent: failed to initialize logging: {e:?}");
    }
    let args = Args::parse(args, &UnixEnvironment, pam_handle)?;
    if args.debug {
        log::set_max_level(log::LevelFilter::Debug);
    }
    do_authenticate(&args, pam_handle)?;
    Ok(())
}

fn do_authenticate(args: &Args, handle: &PamHandle) -> Result<()> {
    let path = get_path(args)?;
    let calling_user = handle.get_calling_user()?;

    info!("Authenticating user '{calling_user}' using ssh-agent at '{path}'");
    if Path::new(&args.file).exists() {
        info!("authorized keys from '{}'", &args.file);
    }
    if let Some(ca_keys_file) = &args.ca_keys_file {
        info!("ca_keys from '{ca_keys_file}'");
    };
    if let Some(authorized_keys_command) = &args.authorized_keys_command {
        info!("Invoking command '{authorized_keys_command}' to obtain keys");
    }

    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;

    let filter = IdentityFilter::new(
        Path::new(args.file.as_str()),
        args.ca_keys_file.as_deref().map(Path::new),
        args.authorized_keys_command.as_deref(),
        args.authorized_keys_command_user.as_deref(),
        &calling_user,
    )?;

    if check_sshd_special_case(
        handle.get_service().ok(),
        &filter,
        UnixEnvironment,
        &calling_user,
    )? {
        return Ok(());
    }
    match authenticate(&filter, ssh_agent_client, &handle.get_calling_user()?)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

/// Implements the sshd special case: when the calling service is `sshd`, the environment
/// variable `SSH_AUTH_INFO_0` holds the key(s) sshd used for its own publickey
/// authentication. If one of them is trusted by `filter` (and, for a certificate, also
/// passes full certificate validation) this returns true and authentication succeeds
/// without a fresh challenge-response round.
///
/// sshd formats each entry as a line led by the method name, e.g.
/// `publickey ssh-ed25519 AAAA...` or `publickey ssh-ed25519-cert-v01@openssh.com AAAA...`.
/// A parse failure for any entry is non-fatal: the entry is skipped and authentication
/// falls back to the normal challenge-response path rather than being denied.
fn check_sshd_special_case(
    service: Option<String>,
    filter: &IdentityFilter,
    env: impl Environment,
    principal: &str,
) -> Result<bool> {
    match service {
        Some(service) => {
            if service != "sshd" {
                return Ok(false);
            }
        }
        None => return Ok(false),
    }
    let Some(info) = env.get_env("SSH_AUTH_INFO_0") else {
        debug!("calling service is sshd but SSH_AUTH_INFO_0 is not set");
        return Ok(false);
    };
    for line in info.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Drop the leading method token ("publickey ") if present; tolerate its absence.
        let entry = line.strip_prefix("publickey ").unwrap_or(line);
        let identity = match parse_auth_info_identity(entry) {
            Ok(identity) => identity,
            Err(e) => {
                debug!("failed to parse SSH_AUTH_INFO_0 entry: {e:?}");
                continue;
            }
        };
        if !filter.filter(&identity) {
            continue;
        }
        match &identity {
            Identity::Certificate(cert) => {
                if validate_cert(cert, SystemTime::now(), principal) {
                    return Ok(true);
                }
            }
            Identity::PublicKey(_) => return Ok(true),
        }
    }
    Ok(false)
}

/// Parse a single `SSH_AUTH_INFO_0` entry (with the leading method token already removed)
/// into an [`Identity`], choosing a certificate or a plain public key based on the key
/// type token.
fn parse_auth_info_identity(entry: &str) -> Result<Identity<'static>> {
    let key_type = entry.split_whitespace().next().unwrap_or_default();
    if key_type.ends_with("-cert-v01@openssh.com") {
        Ok(Certificate::from_openssh(entry)?.into())
    } else {
        Ok(PublicKey::from_openssh(entry)?.into())
    }
}

fn get_path(args: &Args) -> Result<String> {
    match env::var("SSH_AUTH_SOCK") {
        Ok(path) => return Ok(path),
        // It is not an error if this variable is not present, just continue down the function
        Err(VarError::NotPresent) => {}
        Err(_) => {
            return Err(anyhow!("Failed to read environment variable SSH_AUTH_SOCK"));
        }
    }
    match &args.default_ssh_auth_sock {
        Some(path) => Ok(path.to_string()),
        None => Err(anyhow!(
            "SSH_AUTH_SOCK not set and the default_ssh_auth_sock parameter is not set"
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::check_sshd_special_case;
    use crate::filter::IdentityFilter;
    use crate::test::{CERT_STR, CannedEnv, DummyEnv, data};
    use anyhow::Result;
    use std::path::Path;

    // SSH_AUTH_INFO_0-style entries (method token + key) as sshd would set them.
    const AUTH_INFO_MATCHING: &str = "publickey ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAIObUcRy1Nv6fz4xnAXqOaFL/A+gGM9OF+l2qpsDPmMlU test@ed25519";
    const AUTH_INFO_OTHER: &str = "publickey ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAIBEnbbUON/7pV3uMtWfP3eWk9xGVa7qhEb50a5p0zDSk test-ca-key";

    #[test]
    fn test_check_sshd_special_case() -> Result<()> {
        let key = Path::new(data!("id_ed25519.pub"));
        let filter = IdentityFilter::from_authorized_file(key)?;

        // happy path: a "publickey <type> <b64>" entry matching a trusted key
        assert!(check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![AUTH_INFO_MATCHING]),
            "principal",
        )?);

        // a different, untrusted key
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![AUTH_INFO_OTHER]),
            "principal",
        )?);

        // if service is not set, return false (env is never consulted)
        assert!(!check_sshd_special_case(
            None,
            &filter,
            DummyEnv,
            "principal"
        )?);

        // if service is something other than sshd, return false
        assert!(!check_sshd_special_case(
            Some("something".to_string()),
            &filter,
            DummyEnv,
            "principal",
        )?);

        // an unparseable entry is non-fatal: no match, but not an error
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec!["invalid"]),
            "principal",
        )?);

        // a CA-trusted but expired certificate: the filter matches it, but full cert
        // validation rejects it, so the result is false (exercises the certificate path)
        let cert_filter =
            IdentityFilter::from_authorized_file(Path::new(data!("authorized_keys")))?;
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &cert_filter,
            CannedEnv::new(vec![CERT_STR]),
            "principal",
        )?);

        Ok(())
    }
}
