use crate::config::LogFormat;
use tracing::Level;

pub fn init_tracing(level: Level, format: LogFormat) {
    use tracing_subscriber::{filter::LevelFilter, prelude::*};

    let mut plain = None;
    let mut pretty = None;
    #[cfg(feature = "journald")]
    let mut journald = None;
    #[cfg(not(feature = "journald"))]
    let journald: Option<tracing_subscriber::layer::Identity> = None;
    match format {
        LogFormat::Pretty => {
            pretty = Some(tracing_subscriber::fmt::layer().pretty());
        }
        LogFormat::Plain => {
            plain = Some(tracing_subscriber::fmt::layer().compact().with_ansi(false));
        }
        #[cfg(feature = "journald")]
        LogFormat::Journald => match tracing_journald::layer() {
            Ok(journald_layer) => journald = Some(journald_layer),
            Err(e) => {
                eprintln!("Could not initialize journald: {e}");
                plain = Some(tracing_subscriber::fmt::layer().compact().with_ansi(false));
            }
        },
    }

    tracing_subscriber::registry()
        .with(plain)
        .with(pretty)
        .with(journald)
        .with(LevelFilter::from(level))
        .init();
}
