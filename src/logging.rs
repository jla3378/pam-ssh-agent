use anyhow::anyhow;
use log::{Level, Log, Metadata, Record};
use std::cell::Cell;
use std::env;
use std::fmt::Display;
use std::io::Write;
use std::sync::{Arc, Mutex};
use syslog::{Facility, Formatter3164, LogFormat, Logger, LoggerBackend, Severity};

static LOG_LOCK: Mutex<bool> = Mutex::new(false);
thread_local! {
    static REQUEST_DEBUG: Cell<bool> = const { Cell::new(false) };
}

/// This call configures the log crate such that messages logged with log crate
/// macros are sent to the local syslog, prefixed in a way that matches how logging
/// was done in pam_ssh_agent_auth. If this method is called multiple times, subsequent
/// calls will not have any effect.
pub fn init_logging(pam_service: String) -> anyhow::Result<()> {
    let mut guard = LOG_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    if *guard {
        // we have already initialized logging
        return Ok(());
    }

    init_impl(pam_service)?;
    // this will only be reached if init_impl() returned Ok()
    *guard = true;
    Ok(())
}

fn init_impl(pam_service: String) -> anyhow::Result<()> {
    let logger = syslog::unix(PrefixFormatter::new(Facility::LOG_AUTHPRIV, &pam_service))
        .map_err(|e| anyhow!("Failed to set up log: {}", e.description()))?;
    log::set_boxed_logger(Box::new(PrefixWrappingLogger::new(logger)))?;
    log::set_max_level(log::LevelFilter::Debug);
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
        let message = escape_log_value(&message.to_string());
        self.inner
            .format(w, severity, format!("{}{}", self.prefix, message))
    }
}

impl PrefixFormatter {
    fn new(facility: Facility, pam_service: &str) -> Self {
        let inner = Formatter3164 {
            facility,
            hostname: None,
            process: process_name().unwrap_or("unknown".into()),
            pid: std::process::id(),
        };
        PrefixFormatter {
            inner,
            prefix: format!("pam_ssh_agent({}:auth): ", escape_log_value(pam_service)),
        }
    }
}

pub(crate) fn escape_log_value(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\\' => "\\\\".to_owned(),
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            '\t' => "\\t".to_owned(),
            character if character.is_control() => format!("\\u{{{:x}}}", character as u32),
            character => character.to_string(),
        })
        .collect()
}

pub fn process_name() -> anyhow::Result<String> {
    Ok(env::current_exe()?
        .file_name()
        .ok_or(anyhow!("no filename"))?
        .to_string_lossy()
        .into())
}

// PrefixWrappingLogger is a copy of syslog::BasicLogger with the formatter type PrefixFormatter.
// It would be nice to contribute a Log implementation that could hold any Logger
struct PrefixWrappingLogger {
    logger: Arc<Mutex<Logger<LoggerBackend, PrefixFormatter>>>,
}

impl PrefixWrappingLogger {
    fn new(logger: Logger<LoggerBackend, PrefixFormatter>) -> Self {
        PrefixWrappingLogger {
            logger: Arc::new(Mutex::new(logger)),
        }
    }
}

#[allow(unused_variables, unused_must_use)]
impl Log for PrefixWrappingLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info || (metadata.level() == Level::Debug && REQUEST_DEBUG.get())
    }

    fn log(&self, record: &Record) {
        let message = record.args();
        let mut logger = self
            .logger
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match record.level() {
            Level::Error => logger.err(message),
            Level::Warn => logger.warning(message),
            Level::Info => logger.info(message),
            Level::Debug => logger.debug(message),
            Level::Trace => logger.debug(message),
        };
    }

    fn flush(&self) {
        let mut logger = self
            .logger
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _ = logger.backend.flush();
    }
}

#[cfg(test)]
mod test {
    use super::escape_log_value;

    #[test]
    fn escape_log_value_removes_control_characters() {
        assert_eq!(
            escape_log_value("service\r\nuser\t\u{0007}\\key"),
            "service\\r\\nuser\\t\\u{7}\\\\key"
        );
    }
}
