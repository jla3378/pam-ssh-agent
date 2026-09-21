use pam_ssh_agent::filter::IdentityFilter;
use std::hint::black_box;
use std::io::Write;
use std::time::{Duration, Instant};

const WARMUP: usize = 20;
const SAMPLES: usize = 200;
const POLICY: &str = include_str!("../tests/data/authorized_keys");

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
    let _ = std::fs::remove_file(path);
}
