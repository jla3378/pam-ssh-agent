use crate::environment::Environment;
use crate::expansions::expand_vars;
use crate::pamext::PamHandleExt;
use anyhow::{Result, anyhow};
use std::ffi::CStr;
use std::str::from_utf8;

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

        for arg in args.iter().map(|s| s.to_bytes()) {
            match from_utf8(arg)? {
                "debug" => debug = true,
                any => {
                    let any = expand_vars(any.to_string(), env, handle)?;

                    let parts: Vec<&str> = any.splitn(2, '=').collect();
                    if parts.len() != 2 {
                        return Err(anyhow!("Could not split '{any}' using '='"));
                    }
                    let (key, value) = (parts[0], parts[1]);
                    match key {
                        "file" => file = value.into(),
                        "default_ssh_auth_sock" => default_ssh_auth_sock = Some(value.into()),
                        "ca_keys_file" => ca_keys_file = Some(value.into()),
                        "authorized_keys_command" => authorized_keys_command = Some(value.into()),
                        "authorized_keys_command_user" => {
                            authorized_keys_command_user = Some(value.into())
                        }
                        _ => return Err(anyhow!("Unknown parameter key '{key}'")),
                    }
                }
            }
        }
        Ok(Args {
            debug,
            file,
            default_ssh_auth_sock,
            ca_keys_file,
            authorized_keys_command,
            authorized_keys_command_user,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::args::Args;
    use crate::test::{DummyEnv, DummyHandle};
    use anyhow::Result;
    use std::ffi::{CStr, CString};

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
        Ok(())
    }

    // Regression fuzzer for the PAM option parser (split-on-'=', UTF-8 validation, and the
    // variable expansion it triggers on values).
    #[test]
    #[ignore = "fuzz harness; run with: cargo test -- --ignored"]
    fn fuzz_args_parse() {
        use crate::test::{FixedEnv, FixedHandle, Fuzzer, assert_no_panic, fuzz_iters};
        let seeds = [
            "debug",
            "file=/x",
            "file=~/x",
            "ca_keys_file=%h/ca",
            "bad",
            "=",
        ];
        let dict = [
            "debug",
            "file=",
            "ca_keys_file=",
            "authorized_keys_command=",
            "authorized_keys_command_user=",
            "default_ssh_auth_sock=",
            "=",
            "==",
            "a=b=c",
            "%h",
            "%H",
            "%u",
            "%f",
            "%U",
            "~",
            "~bob",
            "/",
        ];
        // Non-panicking fakes: Args::parse runs expand_vars on every non-"debug" arg.
        let env = FixedEnv {
            value: "v".into(),
            uid: 0,
        };
        let handle = FixedHandle {
            user: "u".into(),
            service: "s".into(),
        };
        let mut f = Fuzzer::new(&seeds, &dict);
        for _ in 0..fuzz_iters() {
            // 1-3 args; CString rejects an interior NUL, so strip it before building.
            let raw: Vec<Vec<u8>> = (0..1 + f.any_u64() as usize % 3)
                .map(|_| f.next_bytes().into_iter().filter(|b| *b != 0).collect())
                .collect();
            let owned: Vec<CString> = raw
                .iter()
                .map(|b| CString::new(b.clone()).expect("NUL bytes stripped above"))
                .collect();
            let args: Vec<&CStr> = owned.iter().map(|c| c.as_c_str()).collect();
            let probe = raw.clone();
            assert_no_panic("Args::parse", probe, || {
                let _ = Args::parse(args, &env, &handle);
            });
        }
    }
}
