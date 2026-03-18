use std::fmt;

#[derive(Debug)]
pub struct Config {
    pub port: u16,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidNumber(String),
    MissingArgument(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::InvalidNumber(s) => write!(f, "{} is not a 16 bit number", s),
            ConfigError::MissingArgument(s) => write!(f, "{} is missing its following argument", s),
        }
    }
}

pub fn parse_config() -> Result<Config, ConfigError> {
    let mut config = Config { port: 8053 };

    let mut args = std::env::args().skip(1);
    while args.len() > 0 {
        match args.next().unwrap().as_str() {
            flag @ "-p" | flag @ "--port" => match args.next() {
                Some(s) => {
                    let port =
                        u16::from_str_radix(&s, 10).map_err(|_| ConfigError::InvalidNumber(s))?;
                    config.port = port;
                }
                None => return Err(ConfigError::MissingArgument(flag.to_string())),
            },
            _ => {}
        }
    }

    Ok(config)
}
