// Some common stuff for unit tests. The top level mod statement is gated in a #[cfg(test)]
// conditional, so we don't need to do that for everything in this module

macro_rules! data {
    ($name:expr) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $name)
    };
}

use crate::environment::Environment;
use crate::pamext::PamHandleExt;
use anyhow::Result;
pub(crate) use data;
use std::cell::RefCell;
use std::collections::VecDeque;
use uzers::uid_t;

pub(crate) const CERT_STR: &str = include_str!(data!("cert.pub"));

macro_rules! canned {
    ($name:ident) => {
        pub struct $name {
            answers: RefCell<VecDeque<&'static str>>,
        }

        impl $name {
            pub(crate) fn new(answers: Vec<&'static str>) -> Self {
                $name {
                    answers: RefCell::new(VecDeque::from(answers)),
                }
            }

            fn answer(&'_ self) -> anyhow::Result<String> {
                Ok(self.answers.borrow_mut().pop_front().unwrap().to_string())
            }
        }
    };
}

canned!(CannedEnv);
impl Environment for CannedEnv {
    fn get_homedir(&'_ self, _user: &str) -> Result<String> {
        self.answer()
    }

    fn get_hostname(&'_ self) -> Result<String> {
        self.answer()
    }

    fn get_fqdn(&'_ self) -> Result<String> {
        self.answer()
    }

    fn get_uid(&'_ self, _user: &str) -> anyhow::Result<uid_t> {
        panic!()
    }

    fn get_env(&'_ self, _: &str) -> Option<String> {
        self.answer().ok()
    }
}

canned!(CannedHandler);
impl PamHandleExt for CannedHandler {
    fn get_calling_user(&self) -> Result<String> {
        self.answer()
    }

    fn get_service(&self) -> Result<String> {
        self.answer()
    }
}

pub struct DummyEnv;

impl Environment for DummyEnv {
    fn get_homedir(&'_ self, _user: &str) -> Result<String> {
        panic!()
    }

    fn get_hostname(&'_ self) -> Result<String> {
        panic!()
    }

    fn get_fqdn(&'_ self) -> Result<String> {
        panic!()
    }

    fn get_uid(&'_ self, _user: &str) -> Result<uid_t> {
        panic!()
    }

    fn get_env(&'_ self, _: &str) -> Option<String> {
        panic!()
    }
}

pub struct DummyHandle;

impl PamHandleExt for DummyHandle {
    fn get_calling_user(&self) -> Result<String> {
        panic!()
    }

    fn get_service(&self) -> Result<String> {
        panic!()
    }
}

// ---------------------------------------------------------------------------
// Fuzzing support, shared by the `#[ignore]`d regression fuzz harnesses in the
// individual modules. Run them all with:  cargo test fuzz_ -- --ignored
// Crank the iteration count via the FUZZ_ITERS env var, e.g. FUZZ_ITERS=2000000.

/// Iteration count for the fuzz harnesses (override with FUZZ_ITERS).
pub(crate) fn fuzz_iters() -> usize {
    std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}

/// A tiny deterministic, reproducible source of adversarial byte strings — not
/// cryptographic, just a fixed-seed xorshift PRNG plus a corpus/dictionary
/// mutator used to hammer the hand-written parsers. Seeds and dictionary tokens
/// are target-specific and supplied by each harness.
pub(crate) struct Fuzzer {
    state: u64,
    corpus: Vec<Vec<u8>>,
    dict: Vec<Vec<u8>>,
}

impl Fuzzer {
    pub(crate) fn new(seeds: &[&str], dict: &[&str]) -> Self {
        Fuzzer {
            state: 0x9E37_79B9_7F4A_7C15,
            corpus: seeds.iter().map(|s| s.as_bytes().to_vec()).collect(),
            dict: dict.iter().map(|s| s.as_bytes().to_vec()).collect(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// One arbitrary u64 (for fuzzing numeric inputs like timestamps).
    pub(crate) fn any_u64(&mut self) -> u64 {
        self.next_u64()
    }

    /// A coin flip (for fuzzing bool inputs).
    pub(crate) fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    /// Produce one mutated input as raw bytes (capped at 64 KiB).
    pub(crate) fn next_bytes(&mut self) -> Vec<u8> {
        const CHARS: [char; 8] = ['é', '中', '😀', '\u{0}', '~', '%', '/', '\n'];
        let pick = self.below(self.corpus.len());
        let mut buf = self.corpus[pick].clone();
        for _ in 0..1 + self.below(6) {
            if buf.is_empty() {
                buf.push((self.next_u64() & 0xff) as u8);
                continue;
            }
            match self.next_u64() % 7 {
                0 => {
                    let i = self.below(buf.len());
                    buf[i] = (self.next_u64() & 0xff) as u8;
                }
                1 => {
                    let i = self.below(buf.len() + 1);
                    buf.insert(i, (self.next_u64() & 0xff) as u8);
                }
                2 => {
                    let i = self.below(buf.len());
                    buf.remove(i);
                }
                3 => {
                    let d = self.below(self.dict.len());
                    let tok = self.dict[d].clone();
                    let i = self.below(buf.len() + 1);
                    buf.splice(i..i, tok);
                }
                4 => {
                    let o = self.below(self.corpus.len());
                    let other = self.corpus[o].clone();
                    buf.extend(other);
                }
                5 => {
                    let a = self.below(buf.len());
                    let len = 1 + self.below(buf.len() - a);
                    let slice = buf[a..a + len].to_vec();
                    for _ in 0..self.below(64) {
                        buf.extend_from_slice(&slice);
                    }
                }
                _ => {
                    let c = CHARS[self.below(CHARS.len())];
                    let i = self.below(buf.len() + 1);
                    let mut tmp = [0u8; 4];
                    let enc = c.encode_utf8(&mut tmp).as_bytes().to_vec();
                    buf.splice(i..i, enc);
                }
            }
            buf.truncate(1 << 16);
        }
        buf
    }

    /// One mutated input as a (lossy) String.
    pub(crate) fn next_string(&mut self) -> String {
        String::from_utf8_lossy(&self.next_bytes()).into_owned()
    }
}

/// An `Environment`/`PamHandleExt` fake that returns a fixed (per-instance) value
/// from every method, so a fuzz harness can push adversarial strings through the
/// OS-lookup seam without the fakes themselves erroring or exhausting.
pub(crate) struct FixedEnv {
    pub(crate) value: String,
    pub(crate) uid: uid_t,
}

impl Environment for FixedEnv {
    fn get_homedir(&self, _user: &str) -> Result<String> {
        Ok(self.value.clone())
    }
    fn get_hostname(&self) -> Result<String> {
        Ok(self.value.clone())
    }
    fn get_fqdn(&self) -> Result<String> {
        Ok(self.value.clone())
    }
    fn get_uid(&self, _user: &str) -> Result<uid_t> {
        Ok(self.uid)
    }
    fn get_env(&self, _name: &str) -> Option<String> {
        Some(self.value.clone())
    }
}

pub(crate) struct FixedHandle {
    pub(crate) user: String,
    pub(crate) service: String,
}

impl PamHandleExt for FixedHandle {
    fn get_calling_user(&self) -> Result<String> {
        Ok(self.user.clone())
    }
    fn get_service(&self) -> Result<String> {
        Ok(self.service.clone())
    }
}

/// Run `f`, asserting it does not panic; on panic the message includes `probe`. Removes the
/// repeated catch_unwind boilerplate from the `#[ignore]`d fuzz harnesses.
pub(crate) fn assert_no_panic(label: &str, probe: impl std::fmt::Debug, f: impl FnOnce()) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    assert!(r.is_ok(), "{label} panicked on {probe:?}");
}
