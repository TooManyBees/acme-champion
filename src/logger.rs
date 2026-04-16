use crate::config::LogFormat;
// use tracing::Level;
use log::Level;

pub fn init_logger(level: Level, format: LogFormat) {
    use env_logger::{WriteStyle};

    match format {
        LogFormat::Pretty => {
            env_logger::builder()
                .filter_level(level.to_level_filter())
                .write_style(WriteStyle::Auto)
                .init();
        }
        LogFormat::Plain => {
            env_logger::builder()
                .filter_level(level.to_level_filter())
                .write_style(WriteStyle::Never)
                .init();
        }
        #[cfg(feature = "journald")]
        LogFormat::Journald => match tracing_journald::layer() {
            Ok(journald_layer) => {
                // TODO
            }
            Err(e) => {
                eprintln!("Could not initialize journald: {e}");
                env_logger::builder()
                    .filter_level(level.to_level_filter())
                    .write_style(WriteStyle::Never)
                    .format_timestamp(None)
                    .init();
            }
        },
    }
}
