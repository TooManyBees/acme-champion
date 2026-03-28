use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::Level;

#[derive(Debug)]
pub struct Config {
    pub http_port: u16,
    // pub dns_port: u16,
    pub dns_addr_4: Option<SocketAddr>,
    pub dns_addr_6: Option<SocketAddr>,
    pub loglevel: Level,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidNumber(String),
    InvalidSocket(String),
    MissingArgument(String),
    UnsupportedOption(String, String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::InvalidNumber(s) => write!(f, "{} is not a 16 bit number", s),
            ConfigError::InvalidSocket(s) => write!(f, "{} is not a socket address", s),
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
        dns_addr_4: std::env::var("DNS_ADDR").ok().and_then(|s| s.parse().ok()),
        dns_addr_6: std::env::var("DNS_ADDR_6")
            .ok()
            .and_then(|s| s.parse().ok()),
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
            flag @ "--dns-addr" => match args.next() {
                Some(s) => match s.parse::<SocketAddr>() {
                    Ok(addr) => {
                        if addr.is_ipv4() {
                            config.dns_addr_4 = Some(addr);
                        } else if addr.is_ipv6() {
                            config.dns_addr_6 = Some(addr);
                        }
                    }
                    Err(_) => return Err(ConfigError::InvalidSocket(flag.to_string())),
                },
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

    if config.dns_addr_4.is_none() && config.dns_addr_6.is_none() {
        config.dns_addr_4 = Some(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 5053));
    }

    Ok(config)
}
