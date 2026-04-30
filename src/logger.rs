use crate::config::LogFormat;
use tracing::Level;

pub fn init_logger(level: Level, format: LogFormat) {
    use tracing_subscriber::{filter::LevelFilter, prelude::*};

    let registry = tracing_subscriber::registry().with(LevelFilter::from(level));

    match format {
        LogFormat::Pretty => {
            registry
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
        LogFormat::Plain => {
            registry
                .with(tracing_subscriber::fmt::layer().compact().with_ansi(false))
                .init();
        }
        #[cfg(feature = "journald")]
        LogFormat::Journald => match tracing_journald::layer() {
            Ok(journald_layer) => {
                registry.with(journald_layer).init();
            }
            Err(e) => {
                eprintln!("Could not initialize journald: {e}");
                registry
                    .with(tracing_subscriber::fmt::layer().compact().with_ansi(false))
                    .init();
            }
        },
    }
}
