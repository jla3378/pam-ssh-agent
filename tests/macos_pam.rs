#![cfg(target_os = "macos")]

use pam::constants::{PAM_ESTABLISH_CRED, PamResultCode};
use pam::items::{ItemType, Service, User};
use pam::module::PamHandle;
use pam_ssh_agent::{pam_sm_authenticate, pam_sm_setcred};
use signature::Signer;
use ssh_encoding::{Decode, Encode};
use ssh_key::{PrivateKey, Signature};
use std::ffi::{CString, c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::ptr;
use std::time::Duration;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const c_void,
        handle: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(handle: *mut PamHandle, status: c_int) -> c_int;
    fn pam_set_item(handle: *mut PamHandle, item: c_int, value: *const c_void) -> c_int;
}

struct Handle(*mut PamHandle);

impl Drop for Handle {
    fn drop(&mut self) {
        assert_eq!(unsafe { pam_end(self.0, 0) }, 0);
    }
}

fn serve(listener: UnixListener, mode: &str) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let key = PrivateKey::from_openssh(include_str!("data/id_ed25519")).unwrap();
    let mut length = [0; 4];
    while stream.read_exact(&mut length).is_ok() {
        let mut request = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut request).unwrap();
        let mut response = Vec::new();
        match request[0] {
            11 => {
                response.push(12);
                1u32.encode(&mut response).unwrap();
                key.public_key()
                    .to_bytes()
                    .unwrap()
                    .encode(&mut response)
                    .unwrap();
                "test".encode(&mut response).unwrap();
            }
            13 if mode == "denied" => response.push(5),
            13 => {
                let mut request = &request[1..];
                let _key = Vec::<u8>::decode(&mut request).unwrap();
                let message = Vec::<u8>::decode(&mut request).unwrap();
                let signature: Signature = key.key_data().sign(&message);
                let mut bytes = Vec::new();
                signature.encode(&mut bytes).unwrap();
                response.push(14);
                bytes.encode(&mut response).unwrap();
            }
            message => panic!("unexpected agent message {message}"),
        }
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&response).unwrap();
    }
}

#[test]
fn real_pam_entrypoints() {
    let Ok(mode) = std::env::var("PAM_TEST_MODE") else {
        let directory = std::env::temp_dir().join(format!("pam-agent-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for mode in [
            "success",
            "untrusted",
            "denied",
            "absent",
            "missing-user",
            "missing-service",
        ] {
            let socket = directory.join(mode);
            let server = if matches!(mode, "success" | "untrusted" | "denied") {
                let listener = UnixListener::bind(&socket).unwrap();
                Some(std::thread::spawn(move || serve(listener, mode)))
            } else {
                None
            };
            let result = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "real_pam_entrypoints", "--nocapture"])
                .env("PAM_TEST_MODE", mode)
                .env("SSH_AUTH_SOCK", socket)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{mode}: {}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            if let Some(server) = server {
                server.join().unwrap();
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
        return;
    };
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
    let pam = unsafe { &*handle.0 };
    assert_eq!(pam.get_item::<User>().unwrap().unwrap().0, c"pam-test");
    assert_eq!(pam.get_item::<Service>().unwrap().unwrap().0, c"sudo");
    assert_eq!(
        unsafe { pam.get_data::<u8>("missing").unwrap_err() },
        PamResultCode::PAM_NO_MODULE_DATA
    );
    let null_arg = [ptr::null()];
    for (pointer, argc, argv) in [
        (ptr::null_mut(), 0, ptr::null()),
        (handle.0, -1, ptr::null()),
        (handle.0, 1, ptr::null()),
        (handle.0, 1, null_arg.as_ptr()),
    ] {
        assert_eq!(
            unsafe { pam_sm_authenticate(pointer, 0, argc, argv) },
            PamResultCode::PAM_ABORT
        );
    }
    assert_eq!(
        unsafe { pam::macros::invoke_hook(handle.0, 0, ptr::null(), |_, _| panic!("contained")) },
        PamResultCode::PAM_ABORT
    );
    assert_eq!(
        unsafe { pam_sm_setcred(handle.0, PAM_ESTABLISH_CRED as c_int, 0, ptr::null()) },
        PamResultCode::PAM_SUCCESS
    );
    let invalid = [c"invalid".as_ptr()];
    assert_eq!(
        unsafe { pam_sm_authenticate(handle.0, 0, 1, invalid.as_ptr()) },
        PamResultCode::PAM_AUTH_ERR
    );
    if mode == "missing-user" || mode == "missing-service" {
        let item = if mode == "missing-user" {
            ItemType::User
        } else {
            ItemType::Service
        };
        assert_eq!(
            unsafe { pam_set_item(handle.0, item as c_int, ptr::null()) },
            0
        );
    }
    let file = if mode == "untrusted" {
        "ca_key.pub"
    } else {
        "id_ed25519.pub"
    };
    let arg = CString::new(format!(
        "file={}/tests/data/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let args = [arg.as_ptr()];
    let expected = if mode == "success" {
        PamResultCode::PAM_SUCCESS
    } else {
        PamResultCode::PAM_AUTH_ERR
    };
    assert_eq!(
        unsafe { pam_sm_authenticate(handle.0, 0, 1, args.as_ptr()) },
        expected
    );
}
