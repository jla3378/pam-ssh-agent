use anyhow::anyhow;
use log::{Level, Log, Metadata, Record};
use std::cell::Cell;
use std::env;
use std::fmt::{Display, Write as _};
use std::io::{self, Write};
use std::sync::Mutex;
use syslog::{Facility, Formatter3164, LogFormat, Logger, LoggerBackend, Severity};

static LOG_LOCK: Mutex<bool> = Mutex::new(false);
const MAX_LOG_MESSAGE_BYTES: usize = 1024;
const MAX_LOG_PREFIX_BYTES: usize = 128;
thread_local! {
    static REQUEST_DEBUG: Cell<bool> = const { Cell::new(false) };
}

/// This call configures the log crate such that messages logged with log crate
/// macros are sent to the local syslog, prefixed in a way that matches how logging
/// was done in pam_ssh_agent_auth. If this method is called multiple times, subsequent
/// calls will not have any effect.
pub fn init_logging(pam_service: &str) {
    let Ok(mut guard) = LOG_LOCK.try_lock() else {
        return;
    };
    if *guard {
        // we have already initialized logging
        return;
    }

    if initialization_succeeded(|| init_impl(pam_service)).is_some() {
        *guard = true;
    }
}

fn initialization_succeeded<T>(setup: impl FnOnce() -> anyhow::Result<T>) -> Option<T> {
    setup().ok()
}

fn init_impl(pam_service: &str) -> anyhow::Result<()> {
    let mut logger = syslog::unix(PrefixFormatter::new(Facility::LOG_AUTHPRIV, pam_service))
        .map_err(|e| anyhow!("Failed to set up log: {}", e.description()))?;
    set_nonblocking(&mut logger.backend)?;
    log::set_boxed_logger(Box::new(PrefixWrappingLogger::new(logger)))?;
    log::set_max_level(log::LevelFilter::Debug);
    Ok(())
}

#[cfg(unix)]
fn set_nonblocking(backend: &mut LoggerBackend) -> io::Result<()> {
    match backend {
        LoggerBackend::Unix(socket) => socket.set_nonblocking(true),
        LoggerBackend::UnixStream(socket) => socket.get_mut().set_nonblocking(true),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn set_nonblocking(_backend: &mut LoggerBackend) -> io::Result<()> {
    Ok(())
}

pub fn with_debug<T>(enabled: bool, call: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            REQUEST_DEBUG.set(self.0);
        }
    }
    let previous = REQUEST_DEBUG.replace(enabled);
    let _reset = Reset(previous);
    call()
}

#[derive(Clone)]
struct PrefixFormatter {
    inner: Formatter3164,
    prefix: String,
}

impl<T: Display> LogFormat<T> for PrefixFormatter {
    fn format<W: Write>(&self, w: &mut W, severity: Severity, message: T) -> syslog::Result<()> {
        let message = bounded_escape_log_value(&message.to_string(), MAX_LOG_MESSAGE_BYTES);
        self.inner
            .format(w, severity, format_args!("{}{}", self.prefix, message))
    }
}

impl PrefixFormatter {
    fn new(facility: Facility, pam_service: &str) -> Self {
        let inner = Formatter3164 {
            facility,
            hostname: None,
            process: process_name().unwrap_or_else(|_| "unknown".into()),
            pid: std::process::id(),
        };
        PrefixFormatter {
            inner,
            prefix: format!(
                "pam_ssh_agent({}:auth): ",
                bounded_escape_log_value(pam_service, MAX_LOG_PREFIX_BYTES)
            ),
        }
    }
}

#[cfg(test)]
pub(crate) fn escape_log_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                write!(&mut escaped, "\\u{{{:x}}}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn bounded_escape_log_value(value: &str, max_bytes: usize) -> String {
    let mut escaped = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        let mut encoded = String::new();
        match character {
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character.is_control() => {
                write!(&mut encoded, "\\u{{{:x}}}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => encoded.push(character),
        }
        if escaped.len() + encoded.len() > max_bytes {
            if escaped.len() + '…'.len_utf8() <= max_bytes {
                escaped.push('…');
            }
            break;
        }
        escaped.push_str(&encoded);
    }
    escaped
}

pub fn process_name() -> anyhow::Result<String> {
    Ok(env::current_exe()?
        .file_name()
        .ok_or_else(|| anyhow!("no filename"))?
        .to_string_lossy()
        .into())
}

// PrefixWrappingLogger is a copy of syslog::BasicLogger with the formatter type PrefixFormatter.
// It would be nice to contribute a Log implementation that could hold any Logger
struct PrefixWrappingLogger<B: Write> {
    logger: Mutex<Logger<B, PrefixFormatter>>,
}

impl<B: Write> PrefixWrappingLogger<B> {
    fn new(logger: Logger<B, PrefixFormatter>) -> Self {
        PrefixWrappingLogger {
            logger: Mutex::new(logger),
        }
    }
}

#[allow(unused_variables, unused_must_use)]
impl<B: Write + Send + 'static> Log for PrefixWrappingLogger<B> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info || (metadata.level() == Level::Debug && REQUEST_DEBUG.get())
    }

    fn log(&self, record: &Record) {
        let message = record.args();
        let Ok(mut logger) = self.logger.try_lock() else {
            return;
        };
        match record.level() {
            Level::Error => logger.err(message),
            Level::Warn => logger.warning(message),
            Level::Info => logger.info(message),
            Level::Debug => logger.debug(message),
            Level::Trace => logger.debug(message),
        };
    }

    fn flush(&self) {
        let Ok(mut logger) = self.logger.try_lock() else {
            return;
        };
        let _ = logger.backend.flush();
    }
}

#[cfg(test)]
mod test {
    use super::{Facility, Logger, escape_log_value};
    use log::Log;
    use std::io::{self, Write};

    #[test]
    fn escape_log_value_removes_control_characters() {
        assert_eq!(
            escape_log_value("service\r\nuser\t\u{0007}\\key"),
            "service\\r\\nuser\\t\\u{7}\\\\key"
        );
    }

    #[test]
    fn bounded_escape_limits_untrusted_values() {
        let value = super::bounded_escape_log_value("secret\nvalue", 8);
        assert!(value.len() <= 8);
        assert!(!value.contains('\n'));
        assert_eq!(super::bounded_escape_log_value("123456789", 4), "1234");
    }

    #[test]
    fn initialization_failure_is_nonfatal() {
        let sentinel = 17;
        assert!(
            super::initialization_succeeded(|| Err::<(), _>(anyhow::anyhow!("unavailable")))
                .is_none()
        );
        assert_eq!(sentinel, 17);
    }

    #[test]
    fn would_block_transport_does_not_change_auth_outcome() {
        struct WouldBlock;
        impl Write for WouldBlock {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }

        let logger = super::PrefixWrappingLogger::new(Logger::new(
            WouldBlock,
            super::PrefixFormatter::new(Facility::LOG_AUTHPRIV, "test"),
        ));
        let outcome = 23;
        let record = log::Record::builder()
            .args(format_args!("bounded diagnostic"))
            .level(log::Level::Error)
            .target("test")
            .build();
        let started = std::time::Instant::now();
        logger.log(&record);
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(outcome, 23);
    }

    #[test]
    fn debug_scope_is_thread_local_and_restored() {
        assert!(!super::REQUEST_DEBUG.get());
        super::with_debug(true, || {
            assert!(super::REQUEST_DEBUG.get());
            let thread = std::thread::spawn(|| super::REQUEST_DEBUG.get());
            assert!(!thread.join().expect("thread should finish"));
        });
        assert!(!super::REQUEST_DEBUG.get());
    }
}
