use crate::config::LogFormat;
use crate::time::Time;
use log::Level;
use std::io::Write;
use std::time::SystemTime;

pub fn init_logger(level: Level, format: LogFormat) {
    use env_logger::WriteStyle;

    let mut builder = env_logger::builder();
    let logger = builder
        .filter_level(level.to_level_filter())
        .format_target(false)
        .format(|formatter, record| {
            let now = SystemTime::now();
            let t = Time::from(now);
            let level = record.level();
            let level_style = formatter.default_level_style(level);
            let args = record.args();
            write!(
                formatter,
                "{t} [{level_style}{level:<5}{level_style:#}] {args}"
            )?;

            env_logger::fmt::default_kv_format(formatter, record.key_values())?;
            write!(formatter, "\n")
        })
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
