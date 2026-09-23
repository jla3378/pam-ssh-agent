use crate::environment::Environment;
use crate::expansions::expand_vars;
use crate::pamext::PamHandleExt;
use anyhow::{Result, anyhow};
use std::ffi::CStr;
use std::path::Path;
use std::str::from_utf8;
use std::time::Duration;

const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "/etc/security/authorized_keys";

/// Argument parsing.
#[derive(Debug, Eq, PartialEq)]
pub struct Args {
    pub debug: bool,
    pub file: String,
    pub default_ssh_auth_sock: Option<String>,
    pub ca_keys_file: Option<String>,
    pub authorized_keys_command: Option<String>,
    pub authorized_keys_command_user: Option<String>,
    pub(crate) strict: bool,
    pub(crate) sshd_shortcut: bool,
    pub(crate) agent_timeout: Option<Duration>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            debug: false,
            file: String::from(DEFAULT_AUTHORIZED_KEYS_PATH),
            default_ssh_auth_sock: None,
            ca_keys_file: None,
            authorized_keys_command: None,
            authorized_keys_command_user: None,
            strict: false,
            sshd_shortcut: true,
            agent_timeout: None,
        }
    }
}

impl Args {
    /// Parses args and returns an Args instance with the parsed arguments, expanding any string
    /// parameters according to the "Variable expansions" section in README.md
    pub fn parse(
        args: Vec<&CStr>,
        env: &dyn Environment,
        handle: &dyn PamHandleExt,
    ) -> Result<Self> {
        let mut debug = false;
        let mut file: String = String::from(DEFAULT_AUTHORIZED_KEYS_PATH);
        let mut default_ssh_auth_sock = None;
        let mut ca_keys_file: Option<String> = None;
        let mut authorized_keys_command: Option<String> = None;
        let mut authorized_keys_command_user: Option<String> = None;
        let strict = args.iter().any(|arg| arg.to_bytes() == b"strict");
        let mut sshd_shortcut = !strict;
        let mut agent_timeout = strict.then(|| Duration::from_secs(30));
        let mut file_is_per_user = false;

        for arg in args.iter().map(|s| s.to_bytes()) {
            match from_utf8(arg)? {
                "debug" => debug = true,
                "strict" => {}
                "sshd_shortcut" => sshd_shortcut = true,
                any => {
                    if strict {
                        validate_trust_source_argument(any)?;
                    }
                    if let Some(value) = any.strip_prefix("file=") {
                        file_is_per_user = value.contains("%u");
                    }
                    let any = expand_vars(any.to_string(), env, handle)?;

                    let (key, value) = any
                        .split_once('=')
                        .ok_or_else(|| anyhow!("Could not split '{any}' using '='"))?;
                    match key {
                        "file" => file = value.into(),
                        "default_ssh_auth_sock" => default_ssh_auth_sock = Some(value.into()),
                        "ca_keys_file" => ca_keys_file = Some(value.into()),
                        "authorized_keys_command" => authorized_keys_command = Some(value.into()),
                        "authorized_keys_command_user" => {
                            authorized_keys_command_user = Some(value.into())
                        }
                        "agent_timeout" => {
                            let seconds = value.parse::<u64>()?;
                            if !(1..=300).contains(&seconds) {
                                return Err(anyhow!(
                                    "agent_timeout must be between 1 and 300 seconds"
                                ));
                            }
                            agent_timeout = Some(Duration::from_secs(seconds));
                        }
                        _ => return Err(anyhow!("Unknown parameter key '{key}'")),
                    }
                }
            }
        }
        if strict && !file_is_per_user {
            return Err(anyhow!("strict mode requires file= to contain %u"));
        }
        if strict
            && authorized_keys_command
                .as_deref()
                .is_some_and(|command| !Path::new(command).is_absolute())
        {
            return Err(anyhow!(
                "strict mode requires an absolute authorized_keys_command"
            ));
        }
        Ok(Args {
            debug,
            file,
            default_ssh_auth_sock,
            ca_keys_file,
            authorized_keys_command,
            authorized_keys_command_user,
            strict,
            sshd_shortcut,
            agent_timeout,
        })
    }
}

fn validate_trust_source_argument(argument: &str) -> Result<()> {
    let Some((key, value)) = argument.split_once('=') else {
        return Ok(());
    };
    if !matches!(key, "file" | "ca_keys_file" | "authorized_keys_command") {
        return Ok(());
    }
    if value.contains('~') || value.contains("%h") {
        return Err(anyhow!(
            "strict mode rejects home-expanded trust source '{key}'"
        ));
    }
    if key == "authorized_keys_command"
        && ["%u", "%U", "%H", "%f"]
            .iter()
            .any(|pattern| value.contains(pattern))
    {
        return Err(anyhow!("strict mode rejects expanded helper paths"));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::args::Args;
    use crate::test::{CannedHandler, DummyEnv, DummyHandle};
    use anyhow::Result;
    use std::ffi::{CStr, CString};
    use std::time::Duration;

    struct CStrings {
        inner: Vec<CString>,
    }

    impl CStrings {
        fn refs(&self) -> Vec<&CStr> {
            self.inner.iter().map(CString::as_ref).collect()
        }
    }

    macro_rules! args {
        () => {
            CStrings {inner: Vec::new() }
        };
        ( $( $x:tt ),+ ) => {
            {
                let inner: Vec<CString> = vec![$( $x ),+].iter()
                    .map(|s| CString::new(*s).expect("CString::new failed"))
                    .collect();
                CStrings {inner}
            }
        };
    }

    #[test]
    fn test_parse() -> Result<()> {
        let expected = Args::default();
        assert_eq!(
            expected,
            Args::parse(args!().refs(), &DummyEnv, &DummyHandle)?
        );

        let expected = Args {
            debug: true,
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(args!("debug").refs(), &DummyEnv, &DummyHandle)?
        );

        let expected = Args {
            debug: true,
            file: "/dev/null".into(),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(
                args!("debug", "file=/dev/null").refs(),
                &DummyEnv,
                &DummyHandle
            )?,
        );

        let expected = Args {
            default_ssh_auth_sock: Some("/var/run/ssh_agent.sock".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(
                args!("default_ssh_auth_sock=/var/run/ssh_agent.sock").refs(),
                &DummyEnv,
                &DummyHandle
            )?
        );
        let expected = Args {
            default_ssh_auth_sock: Some("/var/run/ssh=agent.sock".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(
                args!("default_ssh_auth_sock=/var/run/ssh=agent.sock").refs(),
                &DummyEnv,
                &DummyHandle
            )?
        );
        let expected = Args {
            authorized_keys_command: Some("/usr/bin/sss_ssh_authorizedkeys".into()),
            authorized_keys_command_user: Some("nobody".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(
                args!(
                    "authorized_keys_command=/usr/bin/sss_ssh_authorizedkeys",
                    "authorized_keys_command_user=nobody"
                )
                .refs(),
                &DummyEnv,
                &DummyHandle
            )?
        );

        assert_eq!(
            "Could not split 'unknown' using '='",
            Args::parse(args!("unknown").refs(), &DummyEnv, &DummyHandle)
                .unwrap_err()
                .to_string(),
        );

        assert_eq!(
            "Unknown parameter key 'bad_key'",
            Args::parse(args!("bad_key=value").refs(), &DummyEnv, &DummyHandle)
                .unwrap_err()
                .to_string(),
        );

        assert_eq!(
            "invalid utf-8 sequence of 1 bytes from index 0",
            Args::parse(vec![&CString::new(vec![0x80])?], &DummyEnv, &DummyHandle)
                .unwrap_err()
                .to_string(),
        );

        let strict = Args::parse(
            args!(
                "strict",
                "file=/etc/security/pam-ssh-agent/%u",
                "agent_timeout=12"
            )
            .refs(),
            &DummyEnv,
            &CannedHandler::new(vec!["fixture-user"]),
        )?;
        assert!(strict.strict);
        assert!(!strict.sshd_shortcut);
        assert_eq!(strict.file, "/etc/security/pam-ssh-agent/fixture-user");
        assert_eq!(strict.agent_timeout, Some(Duration::from_secs(12)));

        let strict_with_sshd = Args::parse(
            args!(
                "strict",
                "sshd_shortcut",
                "file=/etc/security/pam-ssh-agent/%u"
            )
            .refs(),
            &DummyEnv,
            &CannedHandler::new(vec!["fixture-user"]),
        )?;
        assert!(strict_with_sshd.sshd_shortcut);

        for argument in [
            "file=~/.ssh/authorized_keys",
            "ca_keys_file=%h/ca_keys",
            "authorized_keys_command=~/bin/keys",
        ] {
            let error =
                Args::parse(args!("strict", argument).refs(), &DummyEnv, &DummyHandle).unwrap_err();
            assert!(error.to_string().contains("home-expanded trust source"));
        }
        let error = Args::parse(
            args!("strict", "file=/etc/security/authorized_keys").refs(),
            &DummyEnv,
            &DummyHandle,
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires file= to contain %u"));

        for command in [
            "authorized_keys_command=/usr/libexec/key-%u",
            "authorized_keys_command=/usr/libexec/key-%U",
            "authorized_keys_command=/usr/libexec/key-%H",
            "authorized_keys_command=/usr/libexec/key-%f",
        ] {
            let error = Args::parse(
                args!("strict", "file=/etc/security/pam-ssh-agent/%u", command).refs(),
                &DummyEnv,
                &CannedHandler::new(vec!["fixture-user"]),
            )
            .unwrap_err();
            assert!(error.to_string().contains("expanded helper paths"));
        }
        for argument in [
            "authorized_keys_command=relative-helper",
            "agent_timeout=0",
            "agent_timeout=301",
        ] {
            assert!(
                Args::parse(
                    args!("strict", "file=/etc/security/pam-ssh-agent/%u", argument).refs(),
                    &DummyEnv,
                    &CannedHandler::new(vec!["fixture-user"]),
                )
                .is_err()
            );
        }

        Ok(())
    }
}
