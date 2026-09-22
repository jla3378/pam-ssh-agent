use pam_ssh_agent::filter::IdentityFilter;
use pam_ssh_agent::{SSHAgent, authenticate};
use signature::Signer;
use ssh_agent_client_rs::{Identity, Result as AgentResult};
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::hint::black_box;
use std::io::Write;
use std::time::{Duration, Instant};

const WARMUP: usize = 20;
const SAMPLES: usize = 200;
const POLICY: &str = include_str!("../tests/data/authorized_keys");
const MATCHING_KEY: &str = include_str!("../tests/data/id_ed25519.pub");
const DECOY_KEYS: [&str; 3] = [
    include_str!("../tests/data/ca_key.pub"),
    include_str!("../tests/data/cert_key.pub"),
    include_str!("../tests/data/test_ed25519_sk.pub"),
];

struct InMemoryAgent<'a> {
    identities: &'a [Identity<'static>],
    key: &'a PrivateKey,
}

impl SSHAgent for InMemoryAgent<'_> {
    fn list_identities(&mut self) -> AgentResult<Vec<Identity<'static>>> {
        Ok(self.identities.to_vec())
    }

    fn sign<'a>(&mut self, _key: impl Into<Identity<'a>>, data: &[u8]) -> AgentResult<Signature> {
        Ok(self.key.key_data().sign(data))
    }
}

fn authentication_benchmark(
    filter: &IdentityFilter,
    key: &PrivateKey,
    identities: &[Identity<'static>],
) {
    for _ in 0..WARMUP {
        assert!(
            authenticate(filter, InMemoryAgent { identities, key }, "")
                .expect("authenticate benchmark warmup"),
            "authentication warmup failed"
        );
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let authenticated = authenticate(filter, InMemoryAgent { identities, key }, "")
            .expect("authenticate benchmark");
        samples.push(started.elapsed());
        assert!(authenticated, "authentication benchmark failed");
        black_box(authenticated);
    }

    let p50 = percentile(&mut samples, 50, 100);
    let p95 = percentile(&mut samples, 95, 100);
    let p99 = percentile(&mut samples, 99, 100);
    println!(
        "per-request authentication: identities={} samples={SAMPLES} p50={p50:?} p95={p95:?} p99={p99:?}",
        identities.len()
    );
}

fn percentile(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
    samples.sort_unstable();
    let index = (samples.len() * numerator)
        .div_ceil(denominator)
        .saturating_sub(1);
    samples[index]
}

fn main() {
    let mut random = [0; 16];
    getrandom::fill(&mut random).expect("generate benchmark path");
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = std::env::temp_dir().join(format!(
        "pam-ssh-agent-bench-{}-{suffix}-authorized_keys",
        std::process::id(),
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create benchmark policy");
    file.write_all(POLICY.as_bytes())
        .expect("write benchmark policy");
    drop(file);

    for _ in 0..WARMUP {
        let filter = IdentityFilter::from_authorized_file(&path).expect("parse benchmark policy");
        black_box(filter);
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let filter = IdentityFilter::from_authorized_file(&path).expect("parse benchmark policy");
        black_box(filter);
        samples.push(started.elapsed());
    }

    let p50 = percentile(&mut samples, 50, 100);
    let p95 = percentile(&mut samples, 95, 100);
    let p99 = percentile(&mut samples, 99, 100);
    println!("per-request policy load: samples={SAMPLES} p50={p50:?} p95={p95:?} p99={p99:?}");

    let filter =
        IdentityFilter::from_authorized_file(&path).expect("parse authentication benchmark policy");
    let kind = "PRIVATE";
    let key = PrivateKey::from_openssh(format!(
        "-----BEGIN OPENSSH {kind} KEY-----\n{}-----END OPENSSH {kind} KEY-----\n",
        include_str!("../tests/data/id_ed25519")
    ))
    .expect("parse signing key");
    let matching: Identity<'static> = PublicKey::from_openssh(MATCHING_KEY)
        .expect("parse matching key")
        .into();
    let one_identity = vec![matching.clone()];
    let mut decoys_then_match = DECOY_KEYS
        .iter()
        .map(|key| {
            PublicKey::from_openssh(key)
                .expect("parse decoy key")
                .into()
        })
        .collect::<Vec<Identity<'static>>>();
    decoys_then_match.push(matching);
    authentication_benchmark(&filter, &key, &one_identity);
    authentication_benchmark(&filter, &key, &decoys_then_match);
    let _ = std::fs::remove_file(path);
}
