mod agent;
mod agent_connection;
mod args;
mod auth;
mod cmd;
mod environment;
mod expansions;
pub mod filter;
mod logging;
#[cfg(feature = "native-crypto")]
mod nativecrypto;
mod pamext;
#[cfg(test)]
mod test;
mod verify;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::env::{self, VarError};

use crate::environment::{Environment, UnixEnvironment};
use crate::filter::IdentityFilter;
use crate::logging::{init_logging, with_debug};
use crate::pamext::PamHandleExt;
use anyhow::{Context, Result, anyhow};
use args::Args;
use log::{debug, error, info};
use ssh_key::PublicKey;
use std::ffi::CStr;
use std::path::Path;
use uzers::get_user_by_name;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    /// The authentication method called by pam to authenticate the user. This method
    /// will return PAM_SUCCESS if the ssh-agent available through the unix socket path
    /// in the PAM_AUTH_SOCK environment variable is able to correctly sign a random
    /// message with the private key corresponding to one of the public keys made available
    /// through the args. Otherwise, this function returns PAM_AUTH_ERR.
    /// For the specifics of how the arguments are used to obtain ssh keys
    /// and certificate authority keys, please refer to README.md
    ///
    /// This method logs diagnostic output to the AUTHPRIV syslog facility.
    fn sm_authenticate(
        pam_handle: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        match run(args, pam_handle) {
            Ok(_) => {
                debug!("Successful call to sm_authenticate(), returning PAM_SUCCESS");
                PamResultCode::PAM_SUCCESS
            }
            Err(err) => {
                error!("{err:?}");
                debug!("Failed call to sm_authenticate(), returning PAM_AUTH_ERR");
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    // `doas` calls pam_setcred(), if this is not defined to succeed, it prints
    // a fabulous `doas: pam_setcred(?, PAM_REINITIALIZE_CRED): Permission denied: Unknown error -3`
    fn sm_setcred(
        _pam_handle: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn run(args: Vec<&CStr>, pam_handle: &PamHandle) -> Result<()> {
    let context = PamContext::new(pam_handle)?;
    init_logging(context.service.clone())?;
    let args = Args::parse(args, &UnixEnvironment, &context)?;
    if args.strict {
        let calling_uid = validate_strict_user(&context.calling_user)?;
        if args.authorized_keys_command.is_some() {
            let helper_uid = if let Some(user) = &args.authorized_keys_command_user {
                validate_strict_user(user)?
            } else {
                calling_uid
            };
            if helper_uid == 0 {
                return Err(anyhow!("strict mode requires a non-root helper user"));
            }
        }
    }
    with_debug(args.debug, || do_authenticate(&args, &context))
}

fn do_authenticate(args: &Args, context: &PamContext) -> Result<()> {
    if let Some(ca_keys_file) = &args.ca_keys_file {
        info!("ca_keys from '{ca_keys_file}'");
    };
    if let Some(authorized_keys_command) = &args.authorized_keys_command {
        info!("Invoking command '{authorized_keys_command}' to obtain keys");
    }

    let filter = if args.strict {
        IdentityFilter::new_strict(
            Path::new(args.file.as_str()),
            args.ca_keys_file.as_deref().map(Path::new),
            args.authorized_keys_command.as_deref(),
            args.authorized_keys_command_user.as_deref(),
            &context.calling_user,
        )?
    } else {
        IdentityFilter::new(
            Path::new(args.file.as_str()),
            args.ca_keys_file.as_deref().map(Path::new),
            args.authorized_keys_command.as_deref(),
            args.authorized_keys_command_user.as_deref(),
            &context.calling_user,
        )?
    };
    if args.sshd_shortcut
        && check_sshd_special_case(Some(context.service.clone()), &filter, UnixEnvironment)?
    {
        return Ok(());
    }
    let path = get_path(args)?;
    info!(
        "Authenticating user '{}' using ssh-agent at '{path}'",
        context.calling_user
    );
    info!("authorized keys from '{}'", args.file);
    let ssh_agent_client = agent_connection::connect(Path::new(&path), args.agent_timeout)?;
    match authenticate(&filter, ssh_agent_client, &context.calling_user)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

struct PamContext {
    calling_user: String,
    service: String,
}

impl PamContext {
    fn new(handle: &dyn PamHandleExt) -> Result<Self> {
        Ok(Self {
            calling_user: handle.get_calling_user()?,
            service: handle.get_service()?,
        })
    }
}

impl PamHandleExt for PamContext {
    fn get_calling_user(&self) -> Result<String> {
        Ok(self.calling_user.clone())
    }

    fn get_service(&self) -> Result<String> {
        Ok(self.service.clone())
    }
}

fn validate_strict_user(name: &str) -> Result<u32> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(anyhow!("strict mode requires a plain local user name"));
    }
    let user = get_user_by_name(name)
        .ok_or_else(|| anyhow!("strict mode could not resolve local user '{name}'"))?;
    if user.name().to_string_lossy() != name {
        return Err(anyhow!(
            "strict mode user name does not match the local account"
        ));
    }
    Ok(user.uid())
}

/// Returns true if SSH_SERVICE is sshd, and the environment variable SSH_AUTH_INFO_0 is set
/// to a public key that filter is configured with.
fn check_sshd_special_case(
    service: Option<String>,
    filter: &IdentityFilter,
    env: impl Environment,
) -> Result<bool> {
    match service {
        Some(service) => {
            if service != "sshd" {
                return Ok(false);
            }
        }
        None => return Ok(false),
    }
    let Some(key) = env.get_env("SSH_AUTH_INFO_0") else {
        debug!("calling service is sshd but SSH_AUTH_INFO_0 is not set");
        return Ok(false);
    };
    Ok(filter.filter(
        &PublicKey::from_openssh(&key)
            .context("failed to parse key in SSH_AUTH_INFO_0 environment variable")?
            .into(),
    ))
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
    use crate::filter::IdentityFilter;
    use crate::test::{CannedEnv, DummyEnv, data};
    use crate::{check_sshd_special_case, validate_strict_user};
    use anyhow::Result;
    use std::path::Path;

    #[test]
    fn test_check_sshd_special_case() -> Result<()> {
        let key = Path::new(data!("id_ed25519.pub"));
        let filter = IdentityFilter::from_authorized_file(key)?;

        // happy path, keys match
        assert!(check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![include_str!(data!("id_ed25519.pub"))])
        )?);

        // different key
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![include_str!(data!("ca_key.pub"))])
        )?);

        // if service is not set, return false
        assert!(!check_sshd_special_case(None, &filter, DummyEnv)?);

        // if service is not set to something other than sshd, return false
        assert!(!check_sshd_special_case(
            Some("something".to_string()),
            &filter,
            DummyEnv
        )?);

        // not a key
        assert!(
            check_sshd_special_case(
                Some("sshd".to_string()),
                &filter,
                CannedEnv::new(vec!["invalid"])
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn strict_user_is_local_and_path_safe() {
        for name in ["", "../root", "user/name", "user\nname", ".", "usér"] {
            assert!(validate_strict_user(name).is_err(), "{name:?}");
        }
        assert!(validate_strict_user("codex-account-that-does-not-exist").is_err());
        let current = uzers::get_current_username().expect("current user");
        assert!(validate_strict_user(&current.to_string_lossy()).is_ok());
    }
}
