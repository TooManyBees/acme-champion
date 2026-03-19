use std::fmt;
use std::str::FromStr;
use tracing::Level;

#[derive(Debug)]
pub struct Config {
    pub http_port: u16,
    pub dns_port: u16,
    pub loglevel: Level,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidNumber(String),
    MissingArgument(String),
    UnsupportedOption(String, String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::InvalidNumber(s) => write!(f, "{} is not a 16 bit number", s),
            ConfigError::MissingArgument(s) => write!(f, "{} is missing its following argument", s),
            ConfigError::UnsupportedOption(opt, flag) => {
                write!(f, "{} is not supported for {}", opt, flag)
            }
        }
    }
}

pub fn parse_config() -> Result<Config, ConfigError> {
    let mut config = Config {
        http_port: std::env::var("HTTP_PORT")
            .ok()
            .and_then(|s| u16::from_str(&s).ok())
            .unwrap_or(8053),
        dns_port: std::env::var("DNS_PORT")
            .ok()
            .and_then(|s| u16::from_str(&s).ok())
            .unwrap_or(5053),
        loglevel: std::env::var("LOG_LEVEL")
            .ok()
            .and_then(|s| Level::from_str(&s).ok())
            .unwrap_or(Level::INFO),
    };

    let mut args = std::env::args().skip(1);
    while args.len() > 0 {
        match args.next().unwrap().to_lowercase().as_str() {
            flag @ "--http-port" => match args.next() {
                Some(s) => {
                    let port =
                        u16::from_str_radix(&s, 10).map_err(|_| ConfigError::InvalidNumber(s))?;
                    config.http_port = port;
                }
                None => return Err(ConfigError::MissingArgument(flag.to_string())),
            },
            flag @ "--dns-port" => match args.next() {
                Some(s) => {
                    let port =
                        u16::from_str_radix(&s, 10).map_err(|_| ConfigError::InvalidNumber(s))?;
                    config.dns_port = port;
                }
                None => return Err(ConfigError::MissingArgument(flag.to_string())),
            },
            flag @ "-l" | flag @ "--level" => {
                config.loglevel = match args.next().as_deref() {
                    Some(s) => Level::from_str(s).map_err(|_| {
                        ConfigError::UnsupportedOption(s.to_string(), flag.to_string())
                    })?,
                    None => return Err(ConfigError::MissingArgument(flag.to_string())),
                };
            }
            _ => {}
        }
    }

    Ok(config)
}
