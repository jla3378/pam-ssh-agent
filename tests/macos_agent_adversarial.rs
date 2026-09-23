#![cfg(target_os = "macos")]

use pam::constants::PamResultCode;
use pam::module::PamHandle;
use pam_ssh_agent::{authenticate, filter::IdentityFilter, pam_sm_authenticate};
use signature::Signer;
use ssh_agent_client_rs::{Client, Identity};
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, EcdsaCurve, Mpint, PrivateKey, Signature};
use std::ffi::{CString, c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const c_void,
        handle: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(handle: *mut PamHandle, status: c_int) -> c_int;
}

struct Handle(*mut PamHandle);

impl Drop for Handle {
    fn drop(&mut self) {
        assert_eq!(unsafe { pam_end(self.0, 0) }, 0);
    }
}

struct CaseFixture {
    directory: PathBuf,
    socket: PathBuf,
    metrics: PathBuf,
}

impl Drop for CaseFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.metrics);
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Zero,
    Truncated,
    Oversized,
    WrongType,
    MalformedIdentity,
    Duplicate,
    TrailingIdentity,
    TrailingSignature,
    Disconnect,
    Reset,
    Fragmented,
    Slow,
    Replay,
    WrongKey,
    WrongAlgorithm,
    InvalidSignature,
    ImpossibleCount,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Truncated => "truncated",
            Self::Oversized => "oversized",
            Self::WrongType => "wrong-type",
            Self::MalformedIdentity => "malformed-identity",
            Self::Duplicate => "duplicate",
            Self::TrailingIdentity => "trailing-identity",
            Self::TrailingSignature => "trailing-signature",
            Self::Disconnect => "disconnect",
            Self::Reset => "reset",
            Self::Fragmented => "fragmented",
            Self::Slow => "slow",
            Self::Replay => "replay",
            Self::WrongKey => "wrong-key",
            Self::WrongAlgorithm => "wrong-algorithm",
            Self::InvalidSignature => "invalid-signature",
            Self::ImpossibleCount => "impossible-count",
        }
    }

    fn expected(self) -> PamResultCode {
        if matches!(self, Self::Duplicate | Self::Fragmented) {
            PamResultCode::PAM_SUCCESS
        } else {
            PamResultCode::PAM_AUTH_ERR
        }
    }

    fn category(self) -> &'static str {
        match self {
            Self::Fragmented => "success",
            Self::Slow => "timeout",
            Self::Replay | Self::WrongKey | Self::WrongAlgorithm | Self::InvalidSignature => {
                "verification"
            }
            Self::Duplicate => "recovered-transport",
            Self::Disconnect | Self::Reset => "transport",
            _ => "protocol",
        }
    }

    fn expected_sign_requests(self) -> usize {
        match self {
            Self::Duplicate => 2,
            Self::TrailingSignature => 1,
            Self::Replay
            | Self::WrongKey
            | Self::WrongAlgorithm
            | Self::InvalidSignature
            | Self::Fragmented
            | Self::Slow => 1,
            _ => 0,
        }
    }
}

fn packet(body: &[u8]) -> Vec<u8> {
    let mut result = (body.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(body);
    result
}

fn valid_identity(key: &PrivateKey, count: u32, trailing: bool) -> Vec<u8> {
    let mut body = vec![12];
    count.encode(&mut body).unwrap();
    for _ in 0..count {
        key.public_key()
            .to_bytes()
            .unwrap()
            .encode(&mut body)
            .unwrap();
        b"test".encode(&mut body).unwrap();
    }
    if trailing {
        body.push(0xaa);
    }
    packet(&body)
}

fn write_fragmented(stream: &mut UnixStream, bytes: &[u8]) {
    for byte in bytes {
        stream.write_all(std::slice::from_ref(byte)).unwrap();
        thread::sleep(Duration::from_millis(2));
    }
}

fn read_packet(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let mut body = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn serve(listener: UnixListener, case: Case, sign_requests: Arc<AtomicUsize>) {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return;
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("agent accept failed: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    serve_stream(stream, case, sign_requests);
}

fn serve_stream(mut stream: UnixStream, case: Case, sign_requests: Arc<AtomicUsize>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let key = fixture_key("id_ed25519");
    let wrong_key = fixture_key("ca_key");
    let Ok(request) = read_packet(&mut stream) else {
        return;
    };
    assert_eq!(request, [11], "unexpected identity request");

    match case {
        Case::Truncated => {
            stream.write_all(&[0, 0, 0, 4, 12]).unwrap();
            return;
        }
        Case::Oversized => {
            stream
                .write_all(&u32::to_be_bytes(1024 * 1024 + 1))
                .unwrap();
            return;
        }
        Case::WrongType => {
            stream.write_all(&packet(&[99])).unwrap();
            return;
        }
        Case::Disconnect => {
            return;
        }
        Case::Reset => {
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&raw const linger).cast(),
                        std::mem::size_of_val(&linger) as libc::socklen_t,
                    )
                },
                0
            );
            drop(stream);
            return;
        }
        Case::Zero => {
            stream.write_all(&packet(&[12, 0, 0, 0, 0])).unwrap();
            return;
        }
        Case::ImpossibleCount => {
            stream.write_all(&packet(&[12, 0, 0, 4, 1])).unwrap();
            return;
        }
        Case::MalformedIdentity => {
            let mut body = vec![12, 0, 0, 0, 1];
            3u32.encode(&mut body).unwrap();
            body.extend_from_slice(b"bad");
            0u32.encode(&mut body).unwrap();
            stream.write_all(&packet(&body)).unwrap();
            return;
        }
        Case::TrailingIdentity => {
            stream.write_all(&valid_identity(&key, 1, true)).unwrap();
        }
        Case::TrailingSignature | Case::Duplicate => {
            stream.write_all(&valid_identity(&key, 2, false)).unwrap();
        }
        _ => stream.write_all(&valid_identity(&key, 1, false)).unwrap(),
    }

    let Ok(request) = read_packet(&mut stream) else {
        return;
    };
    assert_eq!(request[0], 13, "unexpected sign request");
    sign_requests.fetch_add(1, Ordering::Relaxed);
    let mut encoded = &request[1..];
    let _identity = Vec::<u8>::decode(&mut encoded).unwrap();
    let message = Vec::<u8>::decode(&mut encoded).unwrap();
    let _flags = u32::decode(&mut encoded).unwrap();
    match case {
        Case::Duplicate => {
            stream.write_all(&packet(&[5])).unwrap();
            let Ok(request) = read_packet(&mut stream) else {
                return;
            };
            assert_eq!(request[0], 13);
            sign_requests.fetch_add(1, Ordering::Relaxed);
            let mut encoded = &request[1..];
            let _ = Vec::<u8>::decode(&mut encoded).unwrap();
            let message = Vec::<u8>::decode(&mut encoded).unwrap();
            let _ = u32::decode(&mut encoded).unwrap();
            write_signature(&mut stream, &key, &message, false);
        }
        Case::Replay => write_signature(&mut stream, &key, b"replayed", false),
        Case::WrongKey => write_signature(&mut stream, &wrong_key, &message, false),
        Case::WrongAlgorithm => {
            let mut data = Vec::new();
            Mpint::from_positive_bytes(&[1])
                .unwrap()
                .encode(&mut data)
                .unwrap();
            Mpint::from_positive_bytes(&[1])
                .unwrap()
                .encode(&mut data)
                .unwrap();
            let signature = Signature::new(
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                },
                data,
            )
            .unwrap();
            let mut body = vec![14];
            let mut bytes = Vec::new();
            signature.encode(&mut bytes).unwrap();
            bytes.encode(&mut body).unwrap();
            stream.write_all(&packet(&body)).unwrap();
        }
        Case::InvalidSignature => stream.write_all(&packet(&[14, 0, 0, 0, 1, 0])).unwrap(),
        Case::Fragmented => {
            let response = signature_packet(&key, &message);
            write_fragmented(&mut stream, &response);
        }
        Case::Slow => {
            let response = signature_packet(&key, &message);
            for byte in response {
                if stream.write_all(std::slice::from_ref(&byte)).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(110));
            }
        }
        Case::TrailingIdentity => write_signature(&mut stream, &key, &message, false),
        Case::TrailingSignature => write_signature(&mut stream, &key, &message, true),
        _ => write_signature(&mut stream, &key, &message, false),
    }
}

fn fixture_key(name: &str) -> PrivateKey {
    let body = match name {
        "id_ed25519" => include_str!("data/id_ed25519"),
        "ca_key" => include_str!("data/ca_key"),
        _ => unreachable!(),
    };
    let label = "OPENSSH PRIVATE KEY";
    PrivateKey::from_openssh(format!(
        "-----BEGIN {label}-----\n{body}-----END {label}-----\n"
    ))
    .unwrap()
}

fn signature_packet(key: &PrivateKey, message: &[u8]) -> Vec<u8> {
    signature_packet_with_trailing(key, message, false)
}

fn signature_packet_with_trailing(key: &PrivateKey, message: &[u8], trailing: bool) -> Vec<u8> {
    let signature = key.key_data().sign(message);
    let mut body = vec![14];
    let mut bytes = Vec::new();
    signature.encode(&mut bytes).unwrap();
    if trailing {
        bytes.push(0xbb);
    }
    bytes.encode(&mut body).unwrap();
    packet(&body)
}

fn write_signature(stream: &mut UnixStream, key: &PrivateKey, message: &[u8], trailing: bool) {
    stream
        .write_all(&signature_packet_with_trailing(key, message, trailing))
        .unwrap();
}

fn pam_child(case: Case) {
    let mut pointer = ptr::null_mut();
    assert_eq!(
        unsafe {
            pam_start(
                c"sudo".as_ptr(),
                c"pam-test".as_ptr(),
                ptr::null(),
                &mut pointer,
            )
        },
        0
    );
    let handle = Handle(pointer);
    let file = CString::new(format!(
        "file={}/tests/data/id_ed25519.pub",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let timeout = c"agent_timeout=1";
    let args = [file.as_ptr(), timeout.as_ptr()];
    let fd_before = fd_count();
    let started = Instant::now();
    let result = unsafe { pam_sm_authenticate(handle.0, 0, args.len() as c_int, args.as_ptr()) };
    drop(handle);
    let wall_us = started.elapsed().as_micros();
    let fd_after = fd_count();
    let max_rss = unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
        usage.ru_maxrss
    };
    let metrics = format!(
        "case={} result={:?} failure_category={} wall_us={} max_rss={} fd_before={} fd_after={}\n",
        case.name(),
        result,
        case.category(),
        wall_us,
        max_rss,
        fd_before,
        fd_after
    );
    std::fs::write(std::env::var_os("PAM_AGENT_METRICS").unwrap(), metrics).unwrap();
    assert!(
        fd_after <= fd_before + 1,
        "case {} leaked file descriptors: {fd_before} -> {fd_after}",
        case.name()
    );
    assert_eq!(result, case.expected(), "case {}", case.name());
}

fn fd_count() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

fn run_case(case: Case) {
    if let Ok(name) = std::env::var("PAM_AGENT_CASE") {
        assert_eq!(name, case.name());
        pam_child(case);
        return;
    }
    let directory = std::env::temp_dir().join(format!(
        "pam-agent-adversarial-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let fixture = CaseFixture {
        socket: directory.join(case.name()),
        metrics: directory.join(format!("{}.metrics", case.name())),
        directory,
    };
    let socket = fixture.socket.clone();
    let metrics = fixture.metrics.clone();
    let sign_requests = Arc::new(AtomicUsize::new(0));
    let listener = UnixListener::bind(&socket).unwrap();
    let server_sign_requests = Arc::clone(&sign_requests);
    let server = thread::spawn(move || serve(listener, case, server_sign_requests));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "adversarial_agent_matrix", "--nocapture"])
        .env("PAM_AGENT_CASE", case.name())
        .env("SSH_AUTH_SOCK", &socket)
        .env("PAM_AGENT_METRICS", &metrics)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    server.join().unwrap();
    let Some(status) = status else {
        panic!("case {} exceeded deadline", case.name());
    };
    assert!(status.success(), "case {} failed", case.name());
    assert_eq!(
        sign_requests.load(Ordering::Relaxed),
        case.expected_sign_requests(),
        "case {} sign-request count",
        case.name()
    );
    let metrics_text = std::fs::read_to_string(&metrics).unwrap();
    assert!(metrics_text.starts_with(&format!("case={} result=", case.name())));
    assert!(metrics_text.contains(&format!("failure_category={}", case.category())));
    assert!(metrics_text.contains("fd_before="));
    assert!(metrics_text.contains("fd_after="));
    eprintln!("{}", metrics_text.trim_end());
    drop(fixture);
}

struct BytewiseIo {
    incoming: Vec<u8>,
    offset: usize,
    outgoing: Arc<Mutex<Vec<u8>>>,
}

impl Read for BytewiseIo {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.offset == self.incoming.len() {
            return Ok(0);
        }
        bytes[0] = self.incoming[self.offset];
        self.offset += 1;
        Ok(1)
    }
}

impl Write for BytewiseIo {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.outgoing.lock().unwrap().push(bytes[0]);
        Ok(1)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn short_read_write_round_trip() {
    let key = fixture_key("id_ed25519");
    let incoming = valid_identity(&key, 1, false);
    let outgoing = Arc::new(Mutex::new(Vec::new()));
    let mut client = Client::with_read_write(Box::new(BytewiseIo {
        incoming,
        offset: 0,
        outgoing: Arc::clone(&outgoing),
    }));
    let identities = client.list_all_identities().unwrap();
    assert_eq!(identities.len(), 1);
    match &identities[0] {
        Identity::PublicKey(public) => {
            assert_eq!(public.key_data(), key.public_key().key_data());
        }
        Identity::Certificate(_) => panic!("short fixture returned a certificate"),
    }
    drop(client);
    assert_eq!(*outgoing.lock().unwrap(), [0, 0, 0, 1, 11]);
}

#[test]
fn duplicate_identity_remote_failure_retries() {
    let (client_stream, server_stream) = UnixStream::pair().unwrap();
    let sign_requests = Arc::new(AtomicUsize::new(0));
    let server_sign_requests = Arc::clone(&sign_requests);
    let server =
        thread::spawn(move || serve_stream(server_stream, Case::Duplicate, server_sign_requests));
    let filter = IdentityFilter::from_authorized_file(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/id_ed25519.pub"
    )))
    .unwrap();
    let client = Client::with_read_write(Box::new(client_stream));
    let result = authenticate(&filter, client, "pam-test");
    server.join().unwrap();
    assert_eq!(sign_requests.load(Ordering::Relaxed), 2);
    assert!(result.unwrap());
}

#[test]
fn adversarial_agent_matrix() {
    if let Ok(name) = std::env::var("PAM_AGENT_CASE") {
        let case = [
            Case::Zero,
            Case::Truncated,
            Case::Oversized,
            Case::WrongType,
            Case::MalformedIdentity,
            Case::Duplicate,
            Case::TrailingIdentity,
            Case::TrailingSignature,
            Case::Disconnect,
            Case::Reset,
            Case::Fragmented,
            Case::Slow,
            Case::Replay,
            Case::WrongKey,
            Case::WrongAlgorithm,
            Case::InvalidSignature,
            Case::ImpossibleCount,
        ]
        .into_iter()
        .find(|case| case.name() == name)
        .unwrap();
        run_case(case);
        return;
    }
    for case in [
        Case::Zero,
        Case::Truncated,
        Case::Oversized,
        Case::WrongType,
        Case::MalformedIdentity,
        Case::Duplicate,
        Case::TrailingIdentity,
        Case::TrailingSignature,
        Case::Disconnect,
        Case::Reset,
        Case::Fragmented,
        Case::Slow,
        Case::Replay,
        Case::WrongKey,
        Case::WrongAlgorithm,
        Case::InvalidSignature,
        Case::ImpossibleCount,
    ] {
        run_case(case);
    }
}
