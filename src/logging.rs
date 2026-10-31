//! A plain stderr logger for journald (`journalctl -u rbkeeperd`).
//!
//! Nothing secret is ever passed to a log macro; this logger additionally strips
//! control characters so a server-supplied string cannot forge extra log lines.
//!
//! Dependencies are held to `Warn` whatever the level: `tungstenite` logs the whole
//! client handshake request — `Authorization: Bearer <device token>` included — at
//! `Trace`, and other crates may do the same with what they carry.

use log::{LevelFilter, Log, Metadata, Record};

struct StderrLogger {
    level: LevelFilter,
}

/// Whether a record reaches the log at `level`: the daemon's own records up to
/// `level`, any dependency's only at `Warn` and above.
pub fn allowed(m: &Metadata<'_>, level: LevelFilter) -> bool {
    let own = m.target() == "rb_keeperd" || m.target().starts_with("rb_keeperd::") || m.target() == "rbkeeperd";
    m.level() <= if own { level } else { level.min(LevelFilter::Warn) }
}

impl Log for StderrLogger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        allowed(m, self.level)
    }

    fn log(&self, r: &Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line: String = r.args().to_string().chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
        eprintln!("{} {}", r.level(), line);
    }

    fn flush(&self) {}
}

/// Install the logger; `RBKEEPERD_LOG=debug` raises the level (the only env the
/// daemon reads, and it is not a secret).
pub fn init() {
    let level = match std::env::var("RBKEEPERD_LOG").as_deref() {
        Ok("debug") => LevelFilter::Debug,
        Ok("warn") => LevelFilter::Warn,
        _ => LevelFilter::Info,
    };
    if log::set_boxed_logger(Box::new(StderrLogger { level })).is_ok() {
        log::set_max_level(level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{Level, MetadataBuilder};

    fn meta(target: &str, level: Level) -> Metadata<'_> {
        MetadataBuilder::new().target(target).level(level).build()
    }

    #[test]
    fn dependencies_are_held_to_warn() {
        let d = LevelFilter::Debug;
        assert!(allowed(&meta("rb_keeperd::daemon", Level::Debug), d));
        assert!(allowed(&meta("rbkeeperd", Level::Info), d));
        assert!(!allowed(&meta("rb_keeperd::daemon", Level::Trace), d));
        assert!(!allowed(&meta("tungstenite::handshake::client", Level::Trace), d));
        assert!(!allowed(&meta("tungstenite::handshake::client", Level::Debug), d));
        assert!(!allowed(&meta("rb_keeperdx", Level::Info), d));
        assert!(allowed(&meta("rustls::conn", Level::Warn), d));
        assert!(!allowed(&meta("rustls::conn", Level::Warn), LevelFilter::Error));
    }
}
