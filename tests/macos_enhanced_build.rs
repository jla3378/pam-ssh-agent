#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

fn plan(settings: &[(&str, &str)]) -> (bool, BTreeMap<String, String>, String) {
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-macos-enhanced.sh");
    let mut command = Command::new(helper);
    command.arg("--plan").env_remove("ENABLE_ENHANCED_SECURITY");
    command
        .env_remove("ENABLE_POINTER_AUTHENTICATION")
        .env_remove("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE");
    for (key, value) in settings {
        command.env(key, value);
    }
    let output = command.output().expect("run enhanced build helper");
    let stdout = String::from_utf8(output.stdout).expect("plan output is UTF-8");
    let values = stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    (output.status.success(), values, stdout)
}

fn assert_plan(settings: &[(&str, &str)], expected: &[(&str, &str)]) {
    let (success, values, stdout) = plan(settings);
    assert!(success, "plan failed:\n{stdout}");
    for (key, value) in expected {
        assert_eq!(values.get(*key).map(String::as_str), Some(*value), "{key}");
    }
}

#[test]
fn plan_defaults_to_arm64_without_hardening() {
    assert_plan(
        &[],
        &[
            ("ENABLE_ENHANCED_SECURITY", "NO"),
            ("ENABLE_POINTER_AUTHENTICATION", "NO"),
            ("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE", "NO"),
            ("ARCHS", "arm64"),
        ],
    );
}

#[test]
fn enhanced_security_enables_pointer_authentication() {
    assert_plan(
        &[("ENABLE_ENHANCED_SECURITY", "YES")],
        &[
            ("ENABLE_ENHANCED_SECURITY", "YES"),
            ("ENABLE_POINTER_AUTHENTICATION", "YES"),
            ("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE", "NO"),
            ("ARCHS", "arm64 arm64e"),
        ],
    );
}

#[test]
fn checked_pointer_arithmetic_can_be_enabled_alone() {
    assert_plan(
        &[("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE", "YES")],
        &[
            ("ENABLE_ENHANCED_SECURITY", "NO"),
            ("ENABLE_POINTER_AUTHENTICATION", "NO"),
            ("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE", "YES"),
            ("ARCHS", "arm64 arm64e.x1"),
        ],
    );
}

#[test]
fn pointer_authentication_and_checked_arithmetic_include_all_slices() {
    assert_plan(
        &[
            ("ENABLE_POINTER_AUTHENTICATION", "YES"),
            ("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE", "YES"),
        ],
        &[
            ("ENABLE_ENHANCED_SECURITY", "NO"),
            ("ENABLE_POINTER_AUTHENTICATION", "YES"),
            ("ENABLE_HARDWARE_CHECKED_POINTER_ARITHMETIC_SLICE", "YES"),
            ("ARCHS", "arm64 arm64e arm64e.x1"),
        ],
    );
}

#[test]
fn invalid_flag_value_fails() {
    let (success, _, _) = plan(&[("ENABLE_POINTER_AUTHENTICATION", "MAYBE")]);
    assert!(!success);
}

#[test]
fn enhanced_security_entitlements_have_required_values() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("support/macos/enhanced-security.entitlements");
    for (key, expected) in [
        ("com.apple.security.hardened-process", "true"),
        (
            "com.apple.security.hardened-process.enhanced-security-version-string",
            "2",
        ),
        (
            "com.apple.security.hardened-process.checked-allocations",
            "true",
        ),
        (
            "com.apple.security.hardened-process.checked-allocations.enforce-checked-pointer-arithmetic-overflow",
            "true",
        ),
    ] {
        let output = Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Print :{key}")])
            .arg(&path)
            .output()
            .expect("read enhanced security entitlement");
        assert!(output.status.success(), "missing entitlement {key}");
        assert_eq!(
            String::from_utf8(output.stdout)
                .expect("entitlement output is UTF-8")
                .trim(),
            expected,
            "{key}"
        );
    }
}
