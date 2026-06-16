use anyhow::{Result, anyhow};
use log::warn;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use wait_timeout::ChildExt;

// macOS's least-privilege account is `nobody`, whose uid and gid are both (gid_t)-2, i.e.
// 4294967294. (This differs from Linux, where the overflow gid 65534 is `nobody`/`nogroup`;
// on macOS gid 65534 maps to no group at all, so dropping to it would be a misconfiguration.)
const DEFAULT_LOW_PRIVILEGE_GID: u32 = 4294967294;

/// Invoke the specified command. If the command does not finish after the specified
/// timeout duration, Err is returned, else the content of stdout from the command is
/// returned. If effective_uid is provided, set the uid of the child process.
pub fn run(
    command: &[&str],
    timeout: Duration,
    effective_uid: u32,
    effective_gid: Option<u32>,
) -> Result<String> {
    let mut cmd = Command::new(command[0]);

    let gid = effective_gid.unwrap_or(DEFAULT_LOW_PRIVILEGE_GID);

    cmd.args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .uid(effective_uid)
        .gid(gid)
        // Put the child in its own process group so we can SIGKILL the whole tree — any
        // grandchildren the command forks that inherit our pipe fds — not just the direct
        // child. Without this, a command that backgrounds a daemon holding stdout open would
        // leave a reader thread blocked on read_to_end (pipe never reaches EOF) and could
        // hang run() past the timeout.
        .process_group(0);

    let mut child = cmd.spawn()?;
    let pgid = child.id() as i32;

    // Capture the pipes; if either is missing (cannot happen with Stdio::piped) kill the
    // child rather than leak it.
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        kill_process_group(pgid);
        return Err(anyhow!(
            "failed to capture stdout/stderr from {}",
            command[0]
        ));
    };

    // Drain stdout and stderr on dedicated threads, concurrently with the wait. Otherwise a
    // command that writes more than the OS pipe buffer (~64KB on macOS) blocks in write()
    // because nothing reads the pipe until the child exits — a deadlock that would make
    // wait_timeout() hit the full timeout and spuriously deny authentication.
    let stdout_reader = drain(stdout);
    let stderr_reader = drain(stderr);

    let status = child.wait_timeout(timeout)?;
    if status.is_none() {
        let _ = child.kill();
    }
    // Reap the whole process group so any grandchildren holding the pipe fds die and the
    // reader threads reach EOF (rather than blocking forever); this also enforces the
    // timeout on a process that forks and lingers. Best-effort — ESRCH on an already-gone
    // group is ignored.
    kill_process_group(pgid);

    let stdout_buf = join_reader(stdout_reader, command[0], "stdout")?;
    let stderr_buf = join_reader(stderr_reader, command[0], "stderr")?;

    let Some(exit_status) = status else {
        return Err(anyhow!(
            "Timed out waiting for command '{}' after {:?}",
            command[0],
            timeout
        ));
    };
    if exit_status.success() {
        if !stderr_buf.is_empty() {
            for line in String::from_utf8_lossy(&stderr_buf).lines() {
                warn!("stderr from {}: {}", command[0], line);
            }
        }
        Ok(String::from_utf8(stdout_buf)?.trim_end().to_owned())
    } else {
        let code = exit_status
            .code()
            .as_ref()
            .map_or("caught signal".into(), i32::to_string);
        Err(anyhow!(
            "Non-zero exit status from '{}': {}",
            command[0],
            code
        ))
    }
}

/// SIGKILL every process in process group `pgid` — the command and any grandchildren it
/// forked that inherited our pipe fds — so the reader threads reach EOF. Best-effort: an
/// empty/already-reaped group returns ESRCH, which is ignored.
fn kill_process_group(pgid: i32) {
    // SAFETY: killpg is a plain syscall with no memory-safety preconditions; its return
    // value (e.g. ESRCH for an already-gone group) is intentionally ignored.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// Spawn a thread that reads `reader` to EOF, so a child writing more than the OS pipe
/// buffer does not block waiting for the parent to drain it.
fn drain<R: Read + Send + 'static>(mut reader: R) -> JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    })
}

/// Join a reader thread started by [`drain`], turning a thread panic or read error into
/// an `anyhow` error.
fn join_reader(
    handle: JoinHandle<std::io::Result<Vec<u8>>>,
    command: &str,
    which: &str,
) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| anyhow!("{which} reader thread for '{command}' panicked"))?
        .map_err(|e| anyhow!("failed to read {which} from '{command}': {e}"))
}

#[cfg(test)]
mod tests {
    use crate::cmd::run;
    use crate::environment::get_uid;
    use anyhow::Result;
    use std::time::Duration;
    use uzers::{get_current_gid, get_current_uid};

    static TIMEOUT: Duration = Duration::from_secs(2);

    // Regression: a command that backgrounds a grandchild which inherits stdout must not hang
    // run() waiting for the pipe to close — the whole process group is killed after the wait,
    // so this returns promptly instead of blocking for the grandchild's lifetime.
    #[test]
    fn test_run_grandchild_does_not_hang() -> Result<()> {
        let start = std::time::Instant::now();
        let out = run(
            &["/bin/sh", "-c", "(sleep 10 &) ; echo done"],
            TIMEOUT,
            get_current_uid(),
            Some(get_current_gid()),
        )?;
        assert_eq!(out, "done");
        assert!(
            start.elapsed() < TIMEOUT,
            "run() should return promptly, took {:?}",
            start.elapsed()
        );
        Ok(())
    }

    #[test]
    fn test_run() -> Result<()> {
        let current_uid = get_current_uid();
        let current_gid = get_current_gid();
        assert_eq!(
            "foo",
            run(&["echo", "foo"], TIMEOUT, current_uid, Some(current_gid))?
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

        let result = run(&["false"], TIMEOUT, current_uid, Some(current_gid));
        let Err(e) = result else {
            panic!("Test expected non-zero exit status");
        };
        assert_eq!(format!("{e}"), "Non-zero exit status from 'false': 1",);

        let result = run(
            &["sleep", "10"],
            Duration::from_millis(100),
            current_uid,
            Some(current_gid),
        );
        let Err(e) = result else {
            panic!("Expected timeout");
        };
        assert_eq!(
            format!("{e}"),
            "Timed out waiting for command 'sleep' after 100ms",
        );

        Ok(())
    }

    // Regression: a command that writes more than the OS pipe buffer (~64KB on macOS) to
    // stdout before exiting previously deadlocked (stdout was only drained after the child
    // was observed to exit), so it spuriously hit the timeout. It must now succeed.
    #[test]
    fn test_run_large_stdout() -> Result<()> {
        let out = run(
            &["/bin/sh", "-c", "yes | head -c 200000"],
            TIMEOUT,
            get_current_uid(),
            Some(get_current_gid()),
        )?;
        assert!(
            out.len() > 100_000,
            "expected >100KB of stdout, got {}",
            out.len()
        );
        Ok(())
    }

    // this test needs to be run as root, so ignoring it during normal testing
    #[ignore]
    #[test]
    fn test_run_with_effective_uid() -> Result<()> {
        let result = run(&["/usr/bin/id"], TIMEOUT, get_uid("nobody")?, None)?;
        assert!(result.contains("nobody"));
        Ok(())
    }
}
