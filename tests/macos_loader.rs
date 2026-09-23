#![cfg(target_os = "macos")]

use signature::Signer;
use ssh_agent_client_rs::{Client, Identity};
use ssh_encoding::{Decode, Encode};
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PAM_SUCCESS: c_int = 0;
const PAM_SYMBOL_ERR: c_int = 2;
const PAM_AUTH_ERR: c_int = 9;
const PAM_ESTABLISH_CRED: c_int = 1;
const PAM_DELETE_CRED: c_int = 2;
const PAM_REINITIALIZE_CRED: c_int = 4;
const PAM_REFRESH_CRED: c_int = 8;
const PAM_USER: c_int = 2;
const PAM_SERVICE: c_int = 1;
const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

#[repr(C)]
struct PamMessage {
    _style: c_int,
    _msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    _resp: *mut c_char,
    _code: c_int,
}

type ConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    data: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_setcred(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_get_item(handle: *const c_void, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_get_user(handle: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> c_int;
}

unsafe extern "C" fn no_op_conv(
    _num_msg: c_int,
    _msg: *mut *const PamMessage,
    _resp: *mut *mut PamResponse,
    _data: *mut c_void,
) -> c_int {
    PAM_SUCCESS
}

struct RootFixture {
    directory: PathBuf,
    service: PathBuf,
    service_name: CString,
}

fn unique_token(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.service);
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn root_file(path: &Path, contents: &[u8], mode: u32) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(path).unwrap();
    file.write_all(contents).unwrap();
    file.sync_all().unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(path.as_ptr(), 0, 0) }, 0);
}

fn fixture(module: &Path, user: &str, policy: &[u8], args: &str) -> RootFixture {
    let (directory, suffix) = loop {
        let suffix = unique_token("pam-ssh-agent-loader");
        let directory = PathBuf::from("/private/etc/security").join(&suffix);
        match std::fs::create_dir(&directory) {
            Ok(()) => break (directory, suffix),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!(
                "create PAM fixture directory {}: {error}",
                directory.display()
            ),
        }
    };
    let service = PathBuf::from("/private/etc/pam.d").join(&suffix);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let service_name = CString::new(service.file_name().unwrap().as_encoded_bytes()).unwrap();
    let fixture = RootFixture {
        directory,
        service,
        service_name,
    };
    root_file(&fixture.directory.join(user), policy, 0o600);
    let line = format!(
        "auth required {} {}\n",
        module.display(),
        args.replace("%POLICY%", &format!("{}/%u", fixture.directory.display()))
    );
    root_file(&fixture.service, line.as_bytes(), 0o600);
    fixture
}

fn assert_secure_fixture(fixture: &RootFixture, user: &str) {
    let directory = std::fs::metadata(&fixture.directory).unwrap();
    assert!(directory.is_dir());
    assert_eq!(directory.uid(), 0);
    assert_eq!(directory.gid(), 0);
    assert_eq!(directory.mode() & 0o7777, 0o700);
    assert_no_extended_acl(&fixture.directory);

    let policy = std::fs::metadata(fixture.directory.join(user)).unwrap();
    assert!(policy.is_file());
    assert_eq!(policy.uid(), 0);
    assert_eq!(policy.gid(), 0);
    assert_eq!(policy.mode() & 0o7777, 0o600);
    assert_eq!(policy.nlink(), 1);
    assert_no_extended_acl(&fixture.directory.join(user));

    let service = std::fs::metadata(&fixture.service).unwrap();
    assert!(service.is_file());
    assert_eq!(service.uid(), 0);
    assert_eq!(service.gid(), 0);
    assert_eq!(service.mode() & 0o7777, 0o600);
    assert_eq!(service.nlink(), 1);
    assert_no_extended_acl(&fixture.service);
}

fn assert_no_extended_acl(path: &Path) {
    let file = std::fs::File::open(path).unwrap();
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if !acl.is_null() {
        assert_eq!(unsafe { acl_free(acl) }, 0);
        panic!("fixture path has an extended ACL: {}", path.display());
    }
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOENT)
    );
}

fn copy_module() -> PathBuf {
    let source = PathBuf::from(std::env::var_os("PAM_LOADER_MODULE").expect("PAM_LOADER_MODULE"));
    let target = PathBuf::from("/private/etc/security")
        .join(unique_token("pam-ssh-agent-loader") + ".dylib");
    let bytes = std::fs::read(source).unwrap();
    root_file(&target, &bytes, 0o755);
    target
}

fn user_name() -> CString {
    let name = std::env::var("PAM_LOADER_USER")
        .or_else(|_| std::env::var("SUDO_USER"))
        .expect("PAM_LOADER_USER or SUDO_USER");
    let account = uzers::get_user_by_name(&name).expect("unknown local user");
    assert_ne!(account.uid(), 0, "PAM_LOADER_USER must not be root");
    assert!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    );
    CString::new(name).unwrap()
}

fn run_pam(service: &CStr, user: &CStr, flags: c_int) -> c_int {
    let before_credentials = credentials();
    let conv = PamConv {
        conv: Some(no_op_conv),
        data: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let start = unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
    if start != PAM_SUCCESS {
        return start;
    }
    for (item, expected) in [(PAM_SERVICE, service), (PAM_USER, user)] {
        let mut value = ptr::null();
        assert_eq!(
            unsafe { pam_get_item(handle, item, &mut value) },
            PAM_SUCCESS
        );
        assert!(!value.is_null());
        assert_eq!(unsafe { CStr::from_ptr(value.cast()) }, expected);
    }
    let mut pam_user = ptr::null();
    assert_eq!(
        unsafe { pam_get_user(handle, &mut pam_user, ptr::null()) },
        PAM_SUCCESS
    );
    assert_eq!(unsafe { CStr::from_ptr(pam_user) }, user);
    let auth_started = Instant::now();
    let auth = unsafe { pam_authenticate(handle, flags) };
    assert!(auth_started.elapsed() < Duration::from_secs(4));
    assert_eq!(
        unsafe { pam_setcred(handle, PAM_ESTABLISH_CRED) },
        PAM_SUCCESS
    );
    assert_eq!(unsafe { pam_setcred(handle, PAM_DELETE_CRED) }, PAM_SUCCESS);
    assert_eq!(
        unsafe { pam_setcred(handle, PAM_REINITIALIZE_CRED) },
        PAM_SUCCESS
    );
    assert_eq!(
        unsafe { pam_setcred(handle, PAM_REFRESH_CRED) },
        PAM_SUCCESS
    );
    assert_eq!(unsafe { pam_setcred(handle, 0x100) }, PAM_SYMBOL_ERR);
    for (item, expected) in [(PAM_SERVICE, service), (PAM_USER, user)] {
        let mut value = ptr::null();
        assert_eq!(
            unsafe { pam_get_item(handle, item, &mut value) },
            PAM_SUCCESS
        );
        assert_eq!(unsafe { CStr::from_ptr(value.cast()) }, expected);
    }
    assert_eq!(unsafe { pam_end(handle, auth) }, PAM_SUCCESS);
    assert_eq!(credentials(), before_credentials);
    auth
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Observation {
    connections: usize,
    identities: usize,
    signs: usize,
}

fn serve(
    listener: UnixListener,
    denied: bool,
    expected_connections: usize,
    stop: Arc<AtomicBool>,
) -> Observation {
    let key = fixture_key();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let observation = Arc::new(Mutex::new(Observation::default()));
    let mut workers = Vec::with_capacity(expected_connections);
    loop {
        if expected_connections > 0
            && observation.lock().unwrap().connections >= expected_connections
        {
            break;
        }
        if expected_connections == 0 && stop.load(Ordering::Acquire) {
            break;
        }
        let connection = loop {
            match listener.accept() {
                Ok(connection) => break Some(connection),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if expected_connections == 0 && stop.load(Ordering::Acquire) {
                        break None;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "fake agent accept deadline exceeded"
                    );
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("fake agent accept failed: {error}"),
            }
        };
        let Some((mut stream, _)) = connection else {
            break;
        };
        observation.lock().unwrap().connections += 1;
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let key = key.clone();
        let observation = Arc::clone(&observation);
        workers.push(thread::spawn(move || {
            loop {
                let mut length = [0; 4];
                if stream.read_exact(&mut length).is_err() {
                    break;
                }
                let mut request = vec![0; u32::from_be_bytes(length) as usize];
                if stream.read_exact(&mut request).is_err() {
                    break;
                }
                let mut response = Vec::new();
                match request.first().copied() {
                    Some(11) => {
                        observation.lock().unwrap().identities += 1;
                        response.push(12);
                        1u32.encode(&mut response).unwrap();
                        key.public_key()
                            .to_bytes()
                            .unwrap()
                            .encode(&mut response)
                            .unwrap();
                        "loader-test".encode(&mut response).unwrap();
                    }
                    Some(13) => {
                        observation.lock().unwrap().signs += 1;
                        if denied {
                            response.push(5);
                        } else {
                            let mut input = &request[1..];
                            let _ = Vec::<u8>::decode(&mut input).unwrap();
                            let message = Vec::<u8>::decode(&mut input).unwrap();
                            let signature: Signature = key.key_data().sign(&message);
                            let mut bytes = Vec::new();
                            signature.encode(&mut bytes).unwrap();
                            response.push(14);
                            bytes.encode(&mut response).unwrap();
                        }
                    }
                    _ => break,
                }
                if stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .is_err()
                    || stream.write_all(&response).is_err()
                {
                    break;
                }
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    Arc::try_unwrap(observation).unwrap().into_inner().unwrap()
}

fn fixture_key() -> PrivateKey {
    let body = include_str!("data/id_ed25519");
    let label = "OPENSSH PRIVATE KEY";
    PrivateKey::from_openssh(format!(
        "-----BEGIN {label}-----\n{body}-----END {label}-----\n"
    ))
    .unwrap()
}

#[test]
fn loader_fixture_key_matches_policy_key() {
    let expected = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();
    assert_eq!(fixture_key().public_key().key_data(), expected.key_data());
}

#[test]
fn loader_agent_identity_matches_policy_key() {
    let socket = SocketCleanup::new();
    let listener = UnixListener::bind(socket.path()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let server = thread::spawn(move || serve(listener, false, 1, server_stop));
    let mut client = Client::connect(socket.path()).unwrap();
    let identities = client.list_all_identities().unwrap();
    assert_eq!(identities.len(), 1);
    let Identity::PublicKey(identity) = &identities[0] else {
        panic!("loader fixture returned a certificate")
    };
    let expected = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();
    assert_eq!(identity.key_data(), expected.key_data());
    client
        .sign_with_ref(&identities[0], b"loader-test")
        .unwrap();
    drop(client);
    stop.store(true, Ordering::Release);
    assert_eq!(
        server.join().unwrap(),
        Observation {
            connections: 1,
            identities: 1,
            signs: 1,
        }
    );
}

struct Metrics {
    started: Instant,
    fds: usize,
    usage: libc::rusage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Credentials {
    uid: libc::uid_t,
    euid: libc::uid_t,
    gid: libc::gid_t,
    egid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

fn credentials() -> Credentials {
    let count = unsafe { libc::getgroups(0, ptr::null_mut()) };
    assert!(count >= 0);
    let mut groups = vec![0; count as usize];
    if count > 0 {
        assert_eq!(
            unsafe { libc::getgroups(count, groups.as_mut_ptr()) },
            count
        );
    }
    Credentials {
        uid: unsafe { libc::getuid() },
        euid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getgid() },
        egid: unsafe { libc::getegid() },
        groups,
    }
}

fn metrics() -> Metrics {
    let mut usage = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
    let fds = std::fs::read_dir("/dev/fd")
        .map(|entries| entries.count())
        .unwrap_or(0);
    Metrics {
        started: Instant::now(),
        fds,
        usage,
    }
}

fn report_metrics(before: Metrics) {
    let after = metrics();
    let cpu_us = |usage: libc::rusage| {
        usage.ru_utime.tv_sec * 1_000_000
            + i64::from(usage.ru_utime.tv_usec)
            + usage.ru_stime.tv_sec * 1_000_000
            + i64::from(usage.ru_stime.tv_usec)
    };
    eprintln!(
        "OpenPAM qualification elapsed_ms={} fd_delta={} cpu_us={} max_rss={}",
        before.started.elapsed().as_millis(),
        after.fds as isize - before.fds as isize,
        cpu_us(after.usage) - cpu_us(before.usage),
        after.usage.ru_maxrss
    );
    assert!(before.started.elapsed() < Duration::from_secs(30));
}

#[test]
#[ignore = "requires root and a staged PAM module; run explicitly in an agent-* tmux session"]
fn openpam_dynamic_loader_qualification() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    let user = user_name();
    let module = copy_module();
    let _module_cleanup = ModuleCleanup(module.clone());
    let key = include_bytes!("data/id_ed25519.pub");
    let bad_key = include_bytes!("data/ca_key.pub");
    let cases = [
        ("success", key.as_slice(), "", PAM_SUCCESS, false, 1, 1, 1),
        (
            "untrusted",
            bad_key.as_slice(),
            "",
            PAM_AUTH_ERR,
            false,
            1,
            1,
            0,
        ),
        ("denied", key.as_slice(), "", PAM_AUTH_ERR, true, 1, 1, 1),
        (
            "malformed",
            b"not-a-key\n".as_slice(),
            "",
            PAM_AUTH_ERR,
            false,
            0,
            0,
            0,
        ),
        (
            "unknown",
            key.as_slice(),
            "unknown=value",
            PAM_AUTH_ERR,
            false,
            0,
            0,
            0,
        ),
    ];
    for (name, policy, extra, expected, denied, connections, identities, signs) in cases {
        let fixture = fixture(
            &module,
            user.to_str().unwrap(),
            policy,
            &format!("strict agent_timeout=2 file=%POLICY% {extra}"),
        );
        assert_secure_fixture(&fixture, user.to_str().unwrap());
        let service = fixture.service_name.as_c_str();
        let socket = SocketCleanup::new();
        let listener = UnixListener::bind(socket.path()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = thread::spawn(move || serve(listener, denied, connections, server_stop));
        unsafe { std::env::set_var("SSH_AUTH_SOCK", socket.path()) };
        let before = metrics();
        let result = run_pam(service, &user, 0);
        stop.store(true, Ordering::Release);
        let observation = server.join().unwrap();
        assert_eq!(
            (
                result,
                observation.connections,
                observation.identities,
                observation.signs,
            ),
            (expected, connections, identities, signs),
            "{name}"
        );
        report_metrics(before);
    }
    let fixture = fixture(
        &module,
        user.to_str().unwrap(),
        key,
        "strict agent_timeout=2 file=%POLICY%",
    );
    assert_secure_fixture(&fixture, user.to_str().unwrap());
    let service = fixture.service_name.as_c_str();
    let mut socket = SocketCleanup::new();
    unsafe { std::env::remove_var("SSH_AUTH_SOCK") };
    assert_eq!(run_pam(service, &user, 0), PAM_AUTH_ERR);
    unsafe { std::env::set_var("SSH_AUTH_SOCK", socket.path()) };
    let listener = UnixListener::bind(socket.path()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let server = thread::spawn(move || serve(listener, false, 3, server_stop));
    for _ in 0..3 {
        assert_eq!(run_pam(service, &user, 0), PAM_SUCCESS);
    }
    let observation = server.join().unwrap();
    assert_eq!(observation.connections, 3);
    assert_eq!(observation.identities, 3);
    assert_eq!(observation.signs, 3);
    stop.store(true, Ordering::Release);
    drop(socket);
    socket = SocketCleanup::new();
    unsafe { std::env::set_var("SSH_AUTH_SOCK", socket.path()) };
    let listener = UnixListener::bind(socket.path()).unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(run_pam(service, &user, 0x4000), PAM_SYMBOL_ERR);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(socket);
    socket = SocketCleanup::new();
    unsafe { std::env::set_var("SSH_AUTH_SOCK", socket.path()) };
    let listener = UnixListener::bind(socket.path()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let server = thread::spawn(move || serve(listener, false, 4, server_stop));
    let service = fixture.service_name.clone();
    let user_for_threads = user.clone();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let service = service.clone();
            let user = user_for_threads.clone();
            thread::spawn(move || run_pam(&service, &user, 0))
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), PAM_SUCCESS);
    }
    stop.store(true, Ordering::Release);
    let observation = server.join().unwrap();
    assert_eq!(observation.connections, 4);
    assert_eq!(observation.identities, 4);
    assert_eq!(observation.signs, 4);
    let before = metrics();
    assert_eq!(run_pam(&service, &user, 0), PAM_AUTH_ERR);
    report_metrics(before);
    let service_path = fixture.service.clone();
    let directory_path = fixture.directory.clone();
    let module_path = module.clone();
    let baseline_fds = metrics().fds;
    drop(fixture);
    drop(_module_cleanup);
    assert!(!service_path.exists());
    assert!(!directory_path.exists());
    assert!(!module_path.exists());
    assert!(metrics().fds <= baseline_fds);
}

struct ModuleCleanup(PathBuf);
impl Drop for ModuleCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct SocketCleanup(PathBuf);

impl SocketCleanup {
    fn new() -> Self {
        Self(std::env::temp_dir().join(unique_token("pam-ssh-agent-loader-socket")))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
