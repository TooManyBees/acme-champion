use crate::config::LogFormat;
use log::Level;

pub fn init_logger(level: Level, format: LogFormat) {
    use env_logger::WriteStyle;

    let mut builder = env_logger::builder();
    let logger = builder
        .filter_level(level.to_level_filter())
        .format_target(false)
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
