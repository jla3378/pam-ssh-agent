use anyhow::Result;
use ssh_agent_client_rs::Client;
use std::io::{Read, Write};
use std::mem::{offset_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn connect(path: &Path, timeout: Option<Duration>) -> Result<Client> {
    let Some(timeout) = timeout else {
        return Ok(Client::connect(path)?);
    };
    let deadline = Instant::now() + timeout;
    let stream = connect_unix(path, deadline)?;
    Ok(Client::with_read_write(Box::new(DeadlineStream {
        stream,
        deadline,
    })))
}

fn connect_unix(path: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let address_len = offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        address.sun_len = u8::try_from(address_len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unix socket path is too long",
            )
        })?;
    }

    let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    set_fd_flags(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC)?;
    let status_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if status_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_fd_flags(
        fd.as_raw_fd(),
        libc::F_SETFL,
        status_flags | libc::O_NONBLOCK,
    )?;

    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            address_len as libc::socklen_t,
        )
    } == 0;
    if !connected {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        wait_for_connect(fd.as_raw_fd(), deadline)?;
    }
    set_fd_flags(fd.as_raw_fd(), libc::F_SETFL, status_flags)?;
    Ok(UnixStream::from(fd))
}

fn set_fd_flags(fd: libc::c_int, command: libc::c_int, flags: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::fcntl(fd, command, flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_connect(fd: libc::c_int, deadline: Instant) -> std::io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH-agent connection timed out",
            ));
        }
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut poll_fd, 1, milliseconds) };
        if result == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH-agent connection timed out",
            ));
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let mut socket_error = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut socket_error).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(std::io::Error::from_raw_os_error(socket_error));
        }
        return Ok(());
    }
}

struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH-agent operation timed out",
            ));
        }
        Ok(remaining)
    }

    fn map_timeout(error: std::io::Error) -> std::io::Error {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH-agent operation timed out",
            )
        } else {
            error
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer).map_err(Self::map_timeout)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer).map_err(Self::map_timeout)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush().map_err(Self::map_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeadlineStream, connect};
    use ssh_agent_client_rs::Client;
    use ssh_encoding::Encode;
    use ssh_key::PublicKey;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn stalled_agent_is_bounded() {
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let _stream = server_stream;
            thread::sleep(Duration::from_millis(200));
        });
        let started = Instant::now();
        let mut client = Client::with_read_write(Box::new(DeadlineStream {
            stream: client_stream,
            deadline: started + Duration::from_millis(50),
        }));
        let error = client.list_all_identities().unwrap_err();
        assert!(format!("{error:?}").contains("SSH-agent operation timed out"));
        assert!(started.elapsed() < Duration::from_millis(180), "{error:?}");
        server.join().unwrap();
    }

    #[test]
    fn stalled_signature_is_bounded_by_the_request_deadline() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut length = [0; 4];
            server_stream.read_exact(&mut length).unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            server_stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [11]);

            let key =
                PublicKey::from_openssh(include_str!("../tests/data/id_ed25519.pub")).unwrap();
            let mut response = vec![12];
            1u32.encode(&mut response).unwrap();
            key.to_bytes().unwrap().encode(&mut response).unwrap();
            "test".encode(&mut response).unwrap();
            server_stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            server_stream.write_all(&response).unwrap();

            server_stream.read_exact(&mut length).unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            server_stream.read_exact(&mut request).unwrap();
            assert_eq!(request[0], 13);
            thread::sleep(Duration::from_millis(200));
        });
        let started = Instant::now();
        let mut client = Client::with_read_write(Box::new(DeadlineStream {
            stream: client_stream,
            deadline: started + Duration::from_millis(75),
        }));
        let identity = client.list_all_identities().unwrap().remove(0);
        let error = client.sign_with_ref(&identity, b"challenge").unwrap_err();
        assert!(format!("{error:?}").contains("SSH-agent operation timed out"));
        assert!(started.elapsed() < Duration::from_millis(180));
        server.join().unwrap();
    }

    #[test]
    fn oversized_agent_response_is_rejected() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let mut request = [0; 5];
            server_stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [0, 0, 0, 1, 11]);
            server_stream
                .write_all(&(1024_u32 * 1024 + 1).to_be_bytes())
                .unwrap();
            server_stream.write_all(&[12]).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let mut client = Client::with_read_write(Box::new(DeadlineStream {
            stream: client_stream,
            deadline: Instant::now() + Duration::from_secs(1),
        }));
        let error = client.list_all_identities().unwrap_err();
        release.send(()).unwrap();
        assert!(format!("{error:?}").contains("larger than 1048576"));
        server.join().unwrap();
    }

    #[test]
    fn rejects_invalid_socket_path() {
        let path = std::path::Path::new("");
        let Err(error) = connect(path, Some(Duration::from_millis(10))) else {
            panic!("empty socket path unexpectedly connected");
        };
        assert!(error.to_string().contains("invalid Unix socket path"));
    }
}
