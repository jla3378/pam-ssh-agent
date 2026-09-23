use anyhow::{Result, anyhow};
use log::warn;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

fn default_low_privilege_gid() -> Result<u32> {
    #[cfg(target_os = "macos")]
    {
        uzers::get_group_by_name("nobody")
            .map(|group| group.gid())
            .ok_or_else(|| anyhow!("Could not find the nobody group"))
    }
    #[cfg(not(target_os = "macos"))]
    Ok(65534)
}

/// Invoke the specified command. If the command does not finish after the specified
/// timeout duration, Err is returned, else the content of stdout from the command is
/// returned. If effective_uid is provided, set the uid of the child process.
pub fn run(
    command: &[&str],
    timeout: Duration,
    effective_uid: u32,
    effective_gid: Option<u32>,
) -> Result<String> {
    run_inner(
        command,
        Instant::now() + timeout,
        Some(timeout),
        effective_uid,
        effective_gid,
        false,
    )
}

pub(crate) fn run_without_descendants(
    command: &[&str],
    timeout: Duration,
    effective_uid: u32,
    effective_gid: Option<u32>,
) -> Result<String> {
    run_inner(
        command,
        Instant::now() + timeout,
        Some(timeout),
        effective_uid,
        effective_gid,
        true,
    )
}

pub(crate) fn run_without_descendants_until(
    command: &[&str],
    deadline: Instant,
    effective_uid: u32,
    effective_gid: Option<u32>,
) -> Result<String> {
    run_inner(command, deadline, None, effective_uid, effective_gid, true)
}

pub(crate) fn run_until(
    command: &[&str],
    deadline: Instant,
    effective_uid: u32,
    effective_gid: Option<u32>,
) -> Result<String> {
    run_inner(command, deadline, None, effective_uid, effective_gid, false)
}

fn run_inner(
    command: &[&str],
    deadline: Instant,
    timeout: Option<Duration>,
    effective_uid: u32,
    effective_gid: Option<u32>,
    prevent_descendants: bool,
) -> Result<String> {
    let executable = command
        .first()
        .ok_or_else(|| anyhow!("command must not be empty"))?;
    if !std::path::Path::new(executable).is_absolute() {
        return Err(anyhow!(
            "command executable must be an absolute path: {executable}"
        ));
    }

    let gid = match effective_gid {
        Some(gid) => gid,
        None => default_low_privilege_gid()?,
    };
    let clear_groups = unsafe { libc::geteuid() } == 0;
    let mut cmd = Command::new(command[0]);

    cmd.args(&command[1..])
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .process_group(0);
    unsafe {
        cmd.pre_exec(move || {
            if prevent_descendants {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_NPROC, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if clear_groups && libc::setgroups(0, ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(effective_uid as libc::uid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    if Instant::now() >= deadline {
        return Err(timeout_error(command[0], timeout));
    }
    let mut child = cmd.spawn()?;
    if Instant::now() >= deadline {
        terminate_and_reap(&mut child);
        return Err(timeout_error(command[0], timeout));
    }
    let streams = (|| -> Result<_> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to get stdout from {}", command[0]))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("failed to get stderr from {}", command[0]))?;
        set_nonblocking(&stdout)?;
        set_nonblocking(&stderr)?;
        Ok((stdout, stderr))
    })();
    let (mut stdout, mut stderr) = match streams {
        Ok(streams) => streams,
        Err(error) => {
            terminate_and_reap(&mut child);
            return Err(error);
        }
    };
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status: Option<ExitStatus> = None;

    loop {
        if let Err(error) = drain_output(&mut stdout, &mut stdout_bytes, &mut stdout_eof) {
            terminate_and_reap(&mut child);
            return Err(anyhow!("failed reading stdout: {error}"));
        }
        if let Err(error) = drain_output(&mut stderr, &mut stderr_bytes, &mut stderr_eof) {
            terminate_and_reap(&mut child);
            return Err(anyhow!("failed reading stderr: {error}"));
        }
        if status.is_some() && stdout_eof && stderr_eof {
            break;
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(result) => status = result,
                Err(error) => {
                    terminate_and_reap(&mut child);
                    return Err(error.into());
                }
            }
        }
        let now = Instant::now();
        if now >= deadline {
            terminate_and_reap(&mut child);
            return Err(timeout_error(command[0], timeout));
        }
        if let Err(error) = wait_for_output(&stdout, stdout_eof, &stderr, stderr_eof, deadline) {
            terminate_and_reap(&mut child);
            return Err(error.into());
        }
    }

    let exit_status = status.ok_or_else(|| anyhow!("command status was not collected"))?;
    if !exit_status.success() {
        let code = exit_status
            .code()
            .map_or("caught signal".into(), |code| code.to_string());
        return Err(anyhow!(
            "Non-zero exit status from '{}': {}",
            command[0],
            code
        ));
    }

    if !stderr_bytes.is_empty() {
        warn!("Configured key helper wrote diagnostic output");
    }
    Ok(String::from_utf8(stdout_bytes)?.trim_end().to_owned())
}

fn timeout_error(command: &str, timeout: Option<Duration>) -> anyhow::Error {
    match timeout {
        Some(timeout) => anyhow!(
            "Timed out waiting for command '{}' after {:?}",
            command,
            timeout
        ),
        None => anyhow!("Timed out waiting for command '{}'", command),
    }
}

fn set_nonblocking(stream: &impl AsRawFd) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_output(
    stdout: &impl AsRawFd,
    stdout_eof: bool,
    stderr: &impl AsRawFd,
    stderr_eof: bool,
    deadline: Instant,
) -> std::io::Result<()> {
    let mut descriptors = [
        libc::pollfd {
            fd: if stdout_eof { -1 } else { stdout.as_raw_fd() },
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        },
        libc::pollfd {
            fd: if stderr_eof { -1 } else { stderr.as_raw_fd() },
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        },
    ];
    let no_open_streams = descriptors.iter().all(|descriptor| descriptor.fd < 0);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        let milliseconds = if no_open_streams {
            remaining.as_millis().clamp(1, 10)
        } else {
            remaining.as_millis().clamp(1, i32::MAX as u128)
        } as i32;
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as _,
                milliseconds,
            )
        };
        if result >= 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn drain_output(
    stream: &mut impl Read,
    output: &mut Vec<u8>,
    eof: &mut bool,
) -> std::io::Result<()> {
    let mut chunk = [0; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(count) if output.len() + count > MAX_OUTPUT_BYTES => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "output limit exceeded",
                ));
            }
            Ok(count) => output.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn terminate_and_reap(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use crate::cmd::{run, run_until, run_without_descendants};
    use crate::environment::get_uid;
    use anyhow::Result;
    use std::time::{Duration, Instant};
    use uzers::{get_current_gid, get_current_uid};

    static TIMEOUT: Duration = Duration::from_secs(2);

    #[cfg(target_os = "macos")]
    #[test]
    fn default_group_matches_directory() {
        assert_eq!(
            super::default_low_privilege_gid().unwrap(),
            uzers::get_group_by_name("nobody").unwrap().gid()
        );
    }

    #[test]
    fn test_run() -> Result<()> {
        let current_uid = get_current_uid();
        let current_gid = get_current_gid();
        assert_eq!(
            "foo",
            run(
                &["/bin/echo", "foo"],
                TIMEOUT,
                current_uid,
                Some(current_gid)
            )?
        );
        assert_eq!(
            "bar",
            run(
                &["/bin/sh", "-c", "echo bar"],
                TIMEOUT,
                current_uid,
                Some(current_gid)
            )?
        );

        let result = run(&["/usr/bin/false"], TIMEOUT, current_uid, Some(current_gid));
        let Err(e) = result else {
            panic!("Test expected non-zero exit status");
        };
        assert_eq!(
            format!("{e}"),
            "Non-zero exit status from '/usr/bin/false': 1",
        );

        let result = run(
            &["/bin/sleep", "10"],
            Duration::from_millis(100),
            current_uid,
            Some(current_gid),
        );
        let Err(e) = result else {
            panic!("Expected timeout");
        };
        assert_eq!(
            format!("{e}"),
            "Timed out waiting for command '/bin/sleep' after 100ms",
        );

        assert!(run(&["echo", "foo"], TIMEOUT, current_uid, Some(current_gid)).is_err());
        let environment = run(&["/usr/bin/env"], TIMEOUT, current_uid, Some(current_gid))?;
        let lines: std::collections::HashSet<_> = environment.lines().collect();
        assert_eq!(
            lines,
            std::collections::HashSet::from(["LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"])
        );

        Ok(())
    }

    #[test]
    fn output_and_descriptor_lifetimes_are_bounded() {
        let uid = get_current_uid();
        let gid = get_current_gid();
        for script in [
            "/usr/bin/yes x | /usr/bin/head -c 1048577",
            "/usr/bin/yes x | /usr/bin/head -c 1048577 >&2",
        ] {
            let error = run(&["/bin/sh", "-c", script], TIMEOUT, uid, Some(gid)).unwrap_err();
            assert!(error.to_string().contains("output limit exceeded"));
        }

        let timeout = Duration::from_millis(100);
        let started = std::time::Instant::now();
        let error = run(
            &["/bin/sh", "-c", "/bin/sleep 10 & exit 0"],
            timeout,
            uid,
            Some(gid),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn expired_deadline_does_not_spawn_helper() {
        let marker = std::env::temp_dir().join(format!(
            "pam-ssh-agent-expired-helper-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);
        let marker = marker.to_string_lossy().into_owned();
        let error = run_until(
            &["/usr/bin/touch", &marker],
            Instant::now() - Duration::from_millis(1),
            get_current_uid(),
            Some(get_current_gid()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Timed out"));
        assert!(!std::path::Path::new(&marker).exists());
    }

    #[test]
    fn strict_helper_cannot_create_descendants() {
        let error = run_without_descendants(
            &["/bin/sh", "-c", "/bin/sleep 1 & wait"],
            TIMEOUT,
            get_current_uid(),
            Some(get_current_gid()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Non-zero exit status"));
    }

    // this test needs to be run as root, so ignoring it during normal testing
    #[ignore]
    #[test]
    fn test_run_with_effective_uid() -> Result<()> {
        let uid = get_uid("nobody")?;
        let gid = super::default_low_privilege_gid()?;
        assert_eq!(
            run(&["/usr/bin/id", "-u"], TIMEOUT, uid, None)?,
            uid.to_string()
        );
        assert_eq!(
            run(&["/usr/bin/id", "-g"], TIMEOUT, uid, None)?,
            gid.to_string()
        );

        #[cfg(target_os = "macos")]
        {
            let probe = r#"import ctypes
import os
libc = ctypes.CDLL(None, use_errno=True)
getgroups = libc.getgroups
getgroups.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
getgroups.restype = ctypes.c_int
count = getgroups(0, None)
if count < 0:
    raise OSError(ctypes.get_errno(), "getgroups")
groups = (ctypes.c_uint32 * count)()
if getgroups(count, groups) != count:
    raise OSError(ctypes.get_errno(), "getgroups")
try:
    os.setuid(0)
except PermissionError:
    pass
else:
    raise RuntimeError("child regained root")
print(*groups)"#;
            let groups = run(&["/usr/bin/python3", "-c", probe], TIMEOUT, uid, None)?;
            assert_eq!(groups, gid.to_string());
        }

        #[cfg(not(target_os = "macos"))]
        {
            let groups = run(&["/usr/bin/id", "-G"], TIMEOUT, uid, None)?;
            assert_eq!(groups.split_whitespace().count(), 1);
        }
        Ok(())
    }
}
