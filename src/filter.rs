use crate::cmd;
use crate::environment::get_uid;
use anyhow::Result;
use anyhow::anyhow;
use log::{debug, info};
use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::Identity::{Certificate, PublicKey};
use ssh_key::AuthorizedKeys;
use ssh_key::public::KeyData;
use std::collections::HashSet;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use uzers::uid_t;

/// An IdentityFilter can determine if an Identity provided by the ssh-agent is trusted or not
/// by this plugin. It is constructed from files or commands providing regular ssh keys or
/// cert-authority keys.
pub struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<KeyData>,
    strict: bool,
}

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_POLICY_ENTRIES: usize = 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PolicyMode {
    Legacy,
    Strict,
}

impl IdentityFilter {
    /// Construct a new Identity filter with the provided authorized_keys file and optionally
    /// also ca_keys_file, authorized_keys_command and authorized_keys_command_user.
    /// The authorized_keys_command will be invoked when specified, and its output will be treated
    /// as additional lines in the authorized_keys file.
    /// If authorized_keys_command_user is not specified, the identity of the calling user will
    /// be used when executing he command.
    pub fn new(
        authorized_keys_file: &Path,
        ca_keys_file: Option<&Path>,
        authorized_keys_command: Option<&str>,
        authorized_keys_command_user: Option<&str>,
        calling_user: &str,
    ) -> Result<Self> {
        Self::new_with_mode(
            authorized_keys_file,
            ca_keys_file,
            authorized_keys_command,
            authorized_keys_command_user,
            calling_user,
            PolicyMode::Legacy,
        )
    }

    pub(crate) fn new_strict(
        authorized_keys_file: &Path,
        ca_keys_file: Option<&Path>,
        authorized_keys_command: Option<&str>,
        authorized_keys_command_user: Option<&str>,
        calling_user: &str,
    ) -> Result<Self> {
        Self::new_with_mode(
            authorized_keys_file,
            ca_keys_file,
            authorized_keys_command,
            authorized_keys_command_user,
            calling_user,
            PolicyMode::Strict,
        )
    }

    fn new_with_mode(
        authorized_keys_file: &Path,
        ca_keys_file: Option<&Path>,
        authorized_keys_command: Option<&str>,
        authorized_keys_command_user: Option<&str>,
        calling_user: &str,
        mode: PolicyMode,
    ) -> Result<Self> {
        let mut identities = match from_file(authorized_keys_file, false, mode) {
            Ok(keys) => keys,
            Err(error)
                if mode == PolicyMode::Legacy
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                if ca_keys_file.is_none() && authorized_keys_command.is_none() {
                    info!(
                        "No valid keys for authentication, {authorized_keys_file:?} does not exist"
                    );
                }
                Vec::new()
            }
            Err(error) => return Err(error),
        };

        if let Some(ca_keys_file) = ca_keys_file {
            identities.extend(from_file(ca_keys_file, true, mode)?);
        }

        if let Some(cmd) = authorized_keys_command {
            let user = authorized_keys_command_user.unwrap_or(calling_user);
            identities.extend(from_command(cmd, get_uid(user)?, calling_user, mode)?);
        }
        Ok(Self::from(identities, mode == PolicyMode::Strict))
    }

    pub fn from_authorized_file(authorized_keys_file: &Path) -> Result<Self> {
        Self::new(authorized_keys_file, None, None, None, "")
    }

    fn from(authorized: Vec<Authorized>, strict: bool) -> Self {
        let (key_count, ca_key_count) =
            authorized
                .iter()
                .fold((0, 0), |(keys, ca_keys), item| match item {
                    Authorized::Key(_) => (keys + 1, ca_keys),
                    Authorized::CAKey(_) => (keys, ca_keys + 1),
                });
        let mut keys = HashSet::with_capacity(key_count);
        let mut ca_keys = HashSet::with_capacity(ca_key_count);

        for item in authorized {
            match item {
                Authorized::Key(key) => keys.insert(key),
                Authorized::CAKey(ca_key) => ca_keys.insert(ca_key),
            };
        }

        Self {
            keys,
            ca_keys,
            strict,
        }
    }

    /// Returns true if the provided Identity is a PublicKey and this filter is configured
    /// with the same public key, or if the Identity is a Certificate and this filter is
    /// configured with a matching cert authority key. Please note that for certificates
    /// this is not enough, see auth::validate_cert for more information.
    pub fn filter(&self, identity: &Identity) -> bool {
        match identity {
            PublicKey(key) => {
                if self.keys.contains(key.key_data()) {
                    debug!(
                        "found a matching key: {}",
                        key.fingerprint(Default::default())
                    );
                    return true;
                }
            }
            Certificate(cert) => {
                let ca_key = cert.signature_key();
                if self.ca_keys.contains(ca_key) {
                    debug!(
                        "found a matching cert-authority key: {}",
                        ca_key.fingerprint(Default::default())
                    );
                    return true;
                }
            }
        }
        false
    }

    pub(crate) fn strict(&self) -> bool {
        self.strict
    }
}

enum Authorized {
    Key(KeyData),
    CAKey(KeyData),
}
const MAX_DURATION: Duration = Duration::from_secs(10);

fn from_command(
    command: &str,
    uid: uid_t,
    calling_user: &str,
    mode: PolicyMode,
) -> Result<Vec<Authorized>> {
    let canonical;
    let command = if mode == PolicyMode::Strict {
        canonical = validate_trust_path(Path::new(command), 0)?;
        canonical
            .to_str()
            .ok_or_else(|| anyhow!("Strict helper path is not valid UTF-8"))?
    } else {
        command
    };
    debug!(
        "Invoking command '{command} {calling_user}' to obtain public keys for user {calling_user}"
    );
    let buf = if mode == PolicyMode::Strict {
        cmd::run_without_descendants(&[command, calling_user], MAX_DURATION, uid, None)?
    } else {
        cmd::run(&[command, calling_user], MAX_DURATION, uid, None)?
    };
    parse_policy(&buf, &format!("{command}:(output):"), false, mode)
}

fn from_file(filename: &Path, ca_keys: bool, mode: PolicyMode) -> Result<Vec<Authorized>> {
    let contents = match mode {
        PolicyMode::Legacy => fs::read_to_string(filename)?,
        PolicyMode::Strict => read_strict_file(filename, 0)?,
    };
    parse_policy(
        &contents,
        filename.to_str().ok_or(anyhow!("invalid filename"))?,
        ca_keys,
        mode,
    )
}

fn parse_policy(buf: &str, what: &str, ca_keys: bool, mode: PolicyMode) -> Result<Vec<Authorized>> {
    if mode == PolicyMode::Strict {
        return from_str_strict(buf, what, ca_keys);
    }
    let keys: AuthorizedKeys = AuthorizedKeys::new(buf);
    let iter = keys.enumerate().filter_map(move |(i, ak)| match ak {
        Ok(entry) => {
            let key_data = entry.public_key().key_data().to_owned();
            if !ca_keys && !entry.config_opts().iter().any(|o| o == "cert-authority") {
                return Some(Authorized::Key(key_data));
            }
            Some(Authorized::CAKey(key_data))
        }
        Err(e) => {
            info!("Failed to parse line {what}:{i}': {e}");
            None
        }
    });
    Ok(iter.collect())
}

fn from_str_strict(buf: &str, what: &str, ca_keys: bool) -> Result<Vec<Authorized>> {
    let mut authorized = Vec::new();
    for (index, entry) in AuthorizedKeys::new(buf).enumerate() {
        let entry =
            entry.map_err(|error| anyhow!("Failed to parse line {what}:{index}: {error}"))?;
        let mut options = entry.config_opts().iter();
        let first_option = options.next();
        let has_only_ca_option = first_option == Some("cert-authority") && options.next().is_none();
        if first_option.is_some() && !has_only_ca_option {
            return Err(anyhow!(
                "Unsupported authorized_keys options at {what}:{index}"
            ));
        }
        let is_ca = ca_keys || has_only_ca_option;
        if authorized.len() >= MAX_POLICY_ENTRIES {
            return Err(anyhow!(
                "Trusted-key policy exceeds {MAX_POLICY_ENTRIES} entries"
            ));
        }
        let key = entry.public_key().key_data().to_owned();
        authorized.push(if is_ca {
            Authorized::CAKey(key)
        } else {
            Authorized::Key(key)
        });
    }
    Ok(authorized)
}

fn read_strict_file(path: &Path, required_uid: u32) -> Result<String> {
    let canonical = validate_trust_path(path, required_uid)?;
    let expected = fs::metadata(&canonical)?;
    let file = File::open(&canonical)?;
    let actual = file.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(anyhow!("Trusted-key file changed while opening"));
    }
    read_bounded(file)
}

fn read_bounded(reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(anyhow!(
            "Trusted-key policy exceeds {MAX_POLICY_BYTES} bytes"
        ));
    }
    Ok(String::from_utf8(bytes)?)
}

fn validate_trust_path(path: &Path, required_uid: u32) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(anyhow!(
            "Strict trusted-key path must be absolute and normalized"
        ));
    }
    validate_components(path, required_uid, true)?;
    let canonical = fs::canonicalize(path)?;
    validate_components(&canonical, required_uid, false)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(anyhow!("Strict trusted-key path is not a regular file"));
    }
    Ok(canonical)
}

fn validate_components(path: &Path, required_uid: u32, allow_symlink: bool) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.uid() != required_uid {
            return Err(anyhow!(
                "Trusted-key path is not owned by uid {required_uid}"
            ));
        }
        if metadata.file_type().is_symlink() {
            if !allow_symlink {
                return Err(anyhow!("Resolved trusted-key path contains a symlink"));
            }
            continue;
        }
        validate_mode(&metadata)?;
    }
    Ok(())
}

fn validate_mode(metadata: &Metadata) -> Result<()> {
    let mode = metadata.mode();
    if mode & 0o022 == 0 {
        return Ok(());
    }
    if is_allowed_sticky_directory(metadata.is_dir(), metadata.uid(), mode) {
        return Ok(());
    }
    Err(anyhow!("Trusted-key path is group- or world-writable"))
}

fn is_allowed_sticky_directory(is_directory: bool, uid: u32, mode: u32) -> bool {
    is_directory && uid == 0 && mode & 0o1000 != 0
}

#[cfg(test)]
mod tests {
    use crate::filter::{
        IdentityFilter, PolicyMode, from_str_strict, read_bounded, validate_trust_path,
    };
    use crate::test::{CERT_STR, data};
    use ssh_agent_client_rs::Identity;
    use ssh_key::{Certificate, PublicKey};
    use std::env;
    use std::path::Path;

    #[test]
    fn test_read_public_keys() -> anyhow::Result<()> {
        let path = Path::new(data!("authorized_keys"));

        let filter = IdentityFilter::from_authorized_file(path)?;

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity));

        // verify that when using the ca_keys_file parameter, we can use the raw key and don't need
        // the 'cert-authority ' prefix.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity));

        // check that we the fact that the authorized_keys file does not exist if ca_keys_file does
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/does/not/exist"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity));

        Ok(())
    }

    #[test]
    fn strict_policy_rejects_options_and_malformed_lines() -> anyhow::Result<()> {
        let key = include_str!(data!("id_ed25519.pub")).trim();
        assert_eq!(from_str_strict(key, "test", false)?.len(), 1);
        assert_eq!(
            from_str_strict(&format!("cert-authority {key}"), "test", false)?.len(),
            1
        );
        assert!(from_str_strict(&format!("restrict {key}"), "test", false).is_err());
        assert!(from_str_strict(&format!("cert-authority,restrict {key}"), "test", false).is_err());
        assert!(from_str_strict(&format!("restrict {key}"), "test", true).is_err());
        assert!(from_str_strict(&format!("command=\"/bin/true\" {key}"), "test", false).is_err());
        assert!(from_str_strict("not a public key", "test", false).is_err());
        assert!(super::parse_policy(key, "test", false, PolicyMode::Strict).is_ok());
        Ok(())
    }

    #[test]
    fn strict_policy_limits_entries_and_bytes() {
        let key = include_str!(data!("id_ed25519.pub")).trim();
        let policy = std::iter::repeat_n(key, super::MAX_POLICY_ENTRIES + 1)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(from_str_strict(&policy, "test", false).is_err());
        assert!(
            read_bounded(std::io::Cursor::new(vec![
                b'x';
                super::MAX_POLICY_BYTES as usize
                    + 1
            ]))
            .is_err()
        );
    }

    #[test]
    fn strict_policy_requires_normalized_absolute_paths() {
        assert!(validate_trust_path(Path::new("relative"), 0).is_err());
        assert!(validate_trust_path(Path::new("/usr/bin/../bin/true"), 0).is_err());
    }

    #[test]
    fn sticky_mode_exception_requires_root_owned_directory() {
        assert!(super::is_allowed_sticky_directory(true, 0, 0o1777));
        assert!(!super::is_allowed_sticky_directory(false, 0, 0o1777));
        assert!(!super::is_allowed_sticky_directory(true, 501, 0o1777));
        assert!(!super::is_allowed_sticky_directory(true, 0, 0o0777));
    }

    // this test needs to be run as root, as otherwise it would not be possible to
    // drop privileges
    #[test]
    #[ignore]
    fn test_invoke_command_for_public_keys() -> anyhow::Result<()> {
        let filter = IdentityFilter::new(
            Path::new("/dev/null"),
            None,
            Some(data!("test.sh")),
            None,
            &env::var("USER")?,
        )?;
        let identity: Identity =
            PublicKey::from_openssh(include_str!(data!("id_ed25519.pub")))?.into();
        assert!(filter.filter(&identity));
        Ok(())
    }
}
