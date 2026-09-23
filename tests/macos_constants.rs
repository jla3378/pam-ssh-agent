#![cfg(target_os = "macos")]

use pam::constants::*;
use pam::items::ItemType;
use std::process::Command;

#[test]
fn constants_match_installed_sdk() {
    let values = [
        (
            "PAM_DOMAIN_UNKNOWN",
            PamResultCode::PAM_DOMAIN_UNKNOWN as i32,
        ),
        ("PAM_REPOSITORY", ItemType::Repository as i32),
        ("PAM_AUTHTOK_PROMPT", ItemType::AuthTokPrompt as i32),
        ("PAM_OLDAUTHTOK_PROMPT", ItemType::OldAuthTokPrompt as i32),
        ("PAM_SUCCESS", PamResultCode::PAM_SUCCESS as i32),
        ("PAM_OPEN_ERR", PamResultCode::PAM_OPEN_ERR as i32),
        ("PAM_SYMBOL_ERR", PamResultCode::PAM_SYMBOL_ERR as i32),
        ("PAM_SERVICE_ERR", PamResultCode::PAM_SERVICE_ERR as i32),
        ("PAM_SYSTEM_ERR", PamResultCode::PAM_SYSTEM_ERR as i32),
        ("PAM_BUF_ERR", PamResultCode::PAM_BUF_ERR as i32),
        ("PAM_CONV_ERR", PamResultCode::PAM_CONV_ERR as i32),
        ("PAM_PERM_DENIED", PamResultCode::PAM_PERM_DENIED as i32),
        ("PAM_MAXTRIES", PamResultCode::PAM_MAXTRIES as i32),
        ("PAM_AUTH_ERR", PamResultCode::PAM_AUTH_ERR as i32),
        (
            "PAM_NEW_AUTHTOK_REQD",
            PamResultCode::PAM_NEW_AUTHTOK_REQD as i32,
        ),
        (
            "PAM_CRED_INSUFFICIENT",
            PamResultCode::PAM_CRED_INSUFFICIENT as i32,
        ),
        (
            "PAM_AUTHINFO_UNAVAIL",
            PamResultCode::PAM_AUTHINFO_UNAVAIL as i32,
        ),
        ("PAM_USER_UNKNOWN", PamResultCode::PAM_USER_UNKNOWN as i32),
        ("PAM_CRED_UNAVAIL", PamResultCode::PAM_CRED_UNAVAIL as i32),
        ("PAM_CRED_EXPIRED", PamResultCode::PAM_CRED_EXPIRED as i32),
        ("PAM_CRED_ERR", PamResultCode::PAM_CRED_ERR as i32),
        ("PAM_ACCT_EXPIRED", PamResultCode::PAM_ACCT_EXPIRED as i32),
        (
            "PAM_AUTHTOK_EXPIRED",
            PamResultCode::PAM_AUTHTOK_EXPIRED as i32,
        ),
        ("PAM_SESSION_ERR", PamResultCode::PAM_SESSION_ERR as i32),
        ("PAM_AUTHTOK_ERR", PamResultCode::PAM_AUTHTOK_ERR as i32),
        (
            "PAM_AUTHTOK_RECOVERY_ERR",
            PamResultCode::PAM_AUTHTOK_RECOVERY_ERR as i32,
        ),
        (
            "PAM_AUTHTOK_LOCK_BUSY",
            PamResultCode::PAM_AUTHTOK_LOCK_BUSY as i32,
        ),
        (
            "PAM_AUTHTOK_DISABLE_AGING",
            PamResultCode::PAM_AUTHTOK_DISABLE_AGING as i32,
        ),
        (
            "PAM_NO_MODULE_DATA",
            PamResultCode::PAM_NO_MODULE_DATA as i32,
        ),
        ("PAM_IGNORE", PamResultCode::PAM_IGNORE as i32),
        ("PAM_ABORT", PamResultCode::PAM_ABORT as i32),
        ("PAM_TRY_AGAIN", PamResultCode::PAM_TRY_AGAIN as i32),
        (
            "PAM_MODULE_UNKNOWN",
            PamResultCode::PAM_MODULE_UNKNOWN as i32,
        ),
        ("PAM_SILENT", PAM_SILENT as i32),
        (
            "PAM_DISALLOW_NULL_AUTHTOK",
            PAM_DISALLOW_NULL_AUTHTOK as i32,
        ),
        ("PAM_ESTABLISH_CRED", PAM_ESTABLISH_CRED as i32),
        ("PAM_DELETE_CRED", PAM_DELETE_CRED as i32),
        ("PAM_REINITIALIZE_CRED", PAM_REINITIALIZE_CRED as i32),
        ("PAM_REFRESH_CRED", PAM_REFRESH_CRED as i32),
        (
            "PAM_CHANGE_EXPIRED_AUTHTOK",
            PAM_CHANGE_EXPIRED_AUTHTOK as i32,
        ),
        ("PAM_SERVICE", ItemType::Service as i32),
        ("PAM_USER", ItemType::User as i32),
        ("PAM_TTY", ItemType::Tty as i32),
        ("PAM_RHOST", ItemType::RHost as i32),
        ("PAM_CONV", ItemType::Conv as i32),
        ("PAM_AUTHTOK", ItemType::AuthTok as i32),
        ("PAM_OLDAUTHTOK", ItemType::OldAuthTok as i32),
        ("PAM_RUSER", ItemType::RUser as i32),
        ("PAM_USER_PROMPT", ItemType::UserPrompt as i32),
    ];
    let directory = std::env::temp_dir().join(format!("pam-sdk-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("constants.c");
    let binary = directory.join("constants");
    let mut code =
        String::from("#include <stdio.h>\n#include <security/pam_modules.h>\nint main(void) {\n");
    for (name, _) in values {
        code.push_str(&format!("printf(\"%d\\n\", (int){name});\n"));
    }
    code.push_str("return 0; }\n");
    std::fs::write(&source, code).unwrap();
    let compiler = std::env::var_os("CC");
    let use_xcrun = compiler.is_none();
    let mut command = Command::new(
        compiler
            .as_deref()
            .unwrap_or_else(|| std::ffi::OsStr::new("xcrun")),
    );
    if use_xcrun {
        command.arg("clang");
    }
    let result = command
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(result.status.success());
    let actual = String::from_utf8(result.stdout).unwrap();
    let actual: Vec<i32> = actual.lines().map(|line| line.parse().unwrap()).collect();
    std::fs::remove_dir_all(directory).unwrap();
    assert_eq!(actual.len(), values.len());
    for ((name, rust), header) in values.into_iter().zip(actual) {
        assert_eq!(rust, header, "{name}");
    }
}
