use crate::config::LogFormat;
use crate::time::Time;
use env_logger::fmt::{Formatter, WriteStyle};
use log::{Level, Record, kv};
use std::io::{self, Write};
use std::time::SystemTime;

pub fn init_logger(level: Level, format: LogFormat) {
    let mut builder = env_logger::builder();
    let logger = builder
        .filter_level(level.to_level_filter())
        .format_target(false)
        .format(format_record)
        .write_style(WriteStyle::Never);

    match format {
        LogFormat::Pretty => {
            logger.write_style(WriteStyle::Auto).init();
        }
        LogFormat::Plain => logger.init(),
        #[cfg(feature = "journald")]
        LogFormat::Journald => {
            if systemd_journal_logger::connected_to_journal() {
                systemd_journal_logger::JournalLog::new()
                    .expect("couldn't connect to journal")
                    .install()
                    .unwrap();
                log::set_max_level(level.to_level_filter());
            } else {
                logger.init();
            }
        }
    }
}

const DIMMED: anstyle::Style = anstyle::Style::new().dimmed();

fn format_record(formatter: &mut Formatter, record: &Record) -> std::io::Result<()> {
    let now = SystemTime::now();
    let t = Time::from(now);
    let level = record.level();
    let level_style = formatter.default_level_style(level);
    let args = record.args();
    write!(
        formatter,
        "{DIMMED}{t}{DIMMED:#} {level_style}{level:<5} {args}{level_style:#}"
    )?;

    record
        .key_values()
        .visit(&mut Visitor { formatter, style: level_style })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    write!(formatter, "\n")
}

struct Visitor<'a> {
    formatter: &'a mut Formatter,
    style: anstyle::Style,
}

static NEEDS_ESCAPE: &'static [char] = &[' ', '"', '\\'];

impl<'kvs> kv::VisitSource<'kvs> for Visitor<'_> {
    fn visit_pair(&mut self, key: kv::Key<'_>, value: kv::Value<'kvs>) -> Result<(), kv::Error> {
        let style = self.style;
        let key_style = self.style.bold();

        write!(self.formatter, " {key_style}{key}{key_style:#}{style}=")?;
        let value_str = value.to_string();
        if value_str.chars().any(|c| NEEDS_ESCAPE.contains(&c)) {
            let escaped_value = value_str.escape_debug().to_string();
            write!(self.formatter, "\"{escaped_value}\"")?;
        } else {
            write!(self.formatter, "{value_str}")?;
        }
        write!(self.formatter, "{style:#}")?;
        Ok(())
    }
}
