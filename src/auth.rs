pub use crate::agent::SSHAgent;
use crate::filter::IdentityFilter;
use crate::verify::verify;
use Identity::{Certificate, PublicKey};
use anyhow::{Result, anyhow};
use log::{debug, info};
use ssh_agent_client_rs::{Error as SACError, Identity};
use ssh_key::{Algorithm, HashAlg, Signature};
use std::time::{SystemTime, UNIX_EPOCH};

const CHALLENGE_SIZE: usize = 32;

/// Finds the first key, if any, that the ssh-agent knows about that is also valid
/// according to filter, sends a random message to be signed and
/// verifies the signature with the public key.
///
/// Returns Ok(true) if a key was found and the signature was correct, Ok(false) if no
/// key was found, and Err if agent communication or signature verification failed.
pub fn authenticate(
    filter: &IdentityFilter,
    mut agent: impl SSHAgent,
    principal: &str,
) -> Result<bool> {
    let strict = filter.strict();
    let now = SystemTime::now();
    for identity in agent.list_identities()? {
        if !filter.filter(&identity) {
            continue;
        }
        if let Certificate(cert) = &identity
            && !validate_cert(cert, now, principal)
        {
            info!("Cert not valid, skipping");
            continue;
        }
        match sign_and_verify(identity, &mut agent, strict) {
            Ok(result) => return Ok(result),
            Err(error)
                if matches!(
                    error.downcast_ref::<SACError>(),
                    Some(SACError::RemoteFailure)
                ) =>
            {
                debug!("SSHAgent: RemoteFailure; trying next key");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn sign_and_verify(
    identity: Identity<'static>,
    agent: &mut impl SSHAgent,
    strict: bool,
) -> Result<bool> {
    let mut data: [u8; CHALLENGE_SIZE] = [0_u8; CHALLENGE_SIZE];
    getrandom::fill(data.as_mut_slice()).map_err(|_| anyhow!("Failed to obtain random data"))?;
    let sig = agent.sign_with_ref(&identity, &data)?;
    if strict {
        validate_sk_signature(&identity, &sig)?;
    }
    let key = match &identity {
        PublicKey(key) => key.key_data(),
        Certificate(cert) => cert.public_key(),
    };
    verify(key, &data, &sig)?;
    Ok(true)
}

fn validate_sk_signature(identity: &Identity, signature: &Signature) -> Result<()> {
    let key = match identity {
        PublicKey(key) => key.key_data(),
        Certificate(cert) => cert.public_key(),
    };
    let expected = if key.is_sk_ed25519() {
        Some(Algorithm::SkEd25519)
    } else if key.is_sk_ecdsa_p256() {
        Some(Algorithm::SkEcdsaSha2NistP256)
    } else {
        None
    };
    let Some(expected) = expected else {
        return Ok(());
    };
    let bytes = signature.as_bytes();
    if signature.algorithm() != expected || bytes.len() < 5 {
        return Err(anyhow!("Invalid security-key signature format"));
    }
    let flags = bytes[bytes.len() - 5];
    if flags & 0x01 == 0 || flags & 0x04 == 0 {
        return Err(anyhow!(
            "Security-key signature requires user presence and verification"
        ));
    }
    Ok(())
}

fn validate_cert(cert: &ssh_key::Certificate, when: SystemTime, principal: &str) -> bool {
    let ca_key = cert.signature_key();

    let Ok(seconds_since_epoch) = when.duration_since(UNIX_EPOCH) else {
        info!("Certificate validation clock precedes Unix epoch");
        return false;
    };

    let ca_fingerprint = ca_key.fingerprint(HashAlg::Sha256);
    if cert
        .validate_at(seconds_since_epoch.as_secs(), [&ca_fingerprint])
        .is_err()
    {
        info!("Certificate validation failed");
        return false;
    }

    if !cert.cert_type().is_user() {
        info!("Cert type is not user, are you trying to authenticate with a host cert?");
        return false;
    }

    if !cert.valid_principals().iter().any(|p| p == principal) {
        info!("Certificate principal validation failed");
        return false;
    }

    if !cert.critical_options().is_empty() {
        info!("Cert has critical options we don't know how to handle");
        return false;
    }

    true
}

#[cfg(test)]
mod test {
    use crate::auth::{validate_cert, validate_sk_signature};
    use crate::test::{CERT_STR, data, private_key};
    use anyhow::Result;
    use ssh_agent_client_rs::Identity;
    use ssh_key::{Algorithm, Certificate, PrivateKey, PublicKey, Signature, certificate};
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_validate_cert() -> Result<()> {
        let cert = Certificate::from_openssh(CERT_STR)?;
        // within validity: 2025-07-15 12:00:00
        assert!(validate_cert(&cert, st(1752577200), "principal"));
        // wrong principal
        assert!(!validate_cert(&cert, st(1752577200), "another"));
        // too early: 2025-06-15 12:00:00
        assert!(!validate_cert(&cert, st(1749985200), "principal"));
        // too late: 2025-08-15 12:00:00
        assert!(!validate_cert(&cert, st(1755255600), "principal"));

        // let's change a byte and check if the signature verification fails
        let mut bytes = CERT_STR.as_bytes().to_vec();
        bytes[90] = 0x42;
        let cert = Certificate::from_openssh(&String::from_utf8_lossy(bytes.as_slice()))?;
        // within validity: 2025-07-15 12:00:00 but the data is scrambled
        assert!(!validate_cert(&cert, st(1752577200), "principal"));

        Ok(())
    }

    #[test]
    fn test_validate_cert_rejects_host_cert() -> Result<()> {
        let cert_key = PrivateKey::from_openssh(private_key("cert_key"))?;
        let ca_key = PrivateKey::from_openssh(private_key("ca_key"))?;

        let mut cert_builder =
            certificate::Builder::new(vec![42; 16], cert_key.public_key(), 1749985200, 1755255600)?;
        cert_builder.cert_type(certificate::CertType::Host)?;
        cert_builder.valid_principal("principal")?;
        let cert = cert_builder.sign(&ca_key)?;

        assert!(!validate_cert(&cert, st(1752577200), "principal"));

        Ok(())
    }

    #[test]
    fn test_unknown_critical_field_in_cert() -> Result<()> {
        let cert = Certificate::from_openssh(include_str!(data!("cert_unknown_critical.pub")))?;
        // within validity: 1999-08-15 12:00:00
        assert!(!validate_cert(&cert, st(934714800), "user"));
        Ok(())
    }

    #[test]
    fn test_validate_cert_rejects_time_before_epoch() -> Result<()> {
        let cert = Certificate::from_openssh(CERT_STR)?;
        assert!(!validate_cert(
            &cert,
            SystemTime::UNIX_EPOCH - Duration::from_secs(1),
            "principal"
        ));
        Ok(())
    }

    #[test]
    fn strict_security_key_requires_presence_and_verification() -> Result<()> {
        let identity: Identity =
            PublicKey::from_openssh(include_str!(data!("test_ed25519_sk.pub")))?.into();
        for (flags, accepted) in [(0x00, false), (0x01, false), (0x04, false), (0x05, true)] {
            let mut bytes = vec![0; 69];
            bytes[64] = flags;
            let signature = Signature::new(Algorithm::SkEd25519, bytes)?;
            assert_eq!(
                validate_sk_signature(&identity, &signature).is_ok(),
                accepted
            );
        }
        let wrong_algorithm = Signature::new(Algorithm::Ed25519, vec![0; 64])?;
        assert!(validate_sk_signature(&identity, &wrong_algorithm).is_err());
        Ok(())
    }

    fn st(timestamp: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp)
    }
}
