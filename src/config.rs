use log::Level;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

pub fn usage() -> String {
    let name = std::env::args()
        .next()
        .and_then(|p| Path::new(&p).file_name().map(|s| s.to_owned()))
        .unwrap_or("acme-champion".into());
    format!(
        "Usage:\t{} [options...]
\t--http-port <PORT> specifies the port that the local API will
\t\tlisten on; defaults to 8053 (the API always listens on
\t\t127.0.0.1)
\t--dns-addr <ADDR> specifies the address that the DNS server will
\t\tlisten on (can be set twice to listen on both ipv4 and ipv6,
\t\tin the form of 0.0.0.0:53 or [::]:53 )
\t--log-level <LEVEL> can be ERROR, WARN, INFO, DEBUG, TRACE
\t--log-format <FORMAT> can be {}
\t--username <USERNAME> changes the process from superuser to this
\t\tuser after binding network ports
\t-h or --help (you're readin' it)",
        name.display(),
        if cfg!(feature = "journald") {
            "PRETTY, PLAIN, JOURNALD"
        } else {
            "PRETTY, PLAIN"
        },
    )
}

#[derive(Debug)]
pub struct Config {
    pub http_port: u16,
    pub dns_addr_4: Option<SocketAddr>,
    pub dns_addr_6: Option<SocketAddr>,
    pub require_v6: bool,
    pub server_ips: ServerIps,
    pub loglevel: Level,
    pub logformat: LogFormat,
    pub username: Option<String>,
}

#[derive(Copy, Clone, Debug)]
pub struct ServerIps {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

#[derive(Copy, Clone, Debug)]
pub enum LogFormat {
    Pretty,
    Plain,
    #[cfg(feature = "journald")]
    Journald,
}

impl LogFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pretty" => Some(LogFormat::Pretty),
            "plain" => Some(LogFormat::Plain),
            #[cfg(feature = "journald")]
            "journald" => Some(LogFormat::Journald),
            _ => None,
        }
    }
    pub fn default() -> Self {
        if cfg!(debug_assertions) {
            LogFormat::Pretty
        } else {
            LogFormat::Plain
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidNumber(String),
    InvalidAddr(String),
    UnsupportedAddrs(String),
    MissingArgument(String),
    UnsupportedOption(String, String),
    JustPrintUsage,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::InvalidNumber(s) => write!(f, "{} is not a 16 bit number", s),
            ConfigError::InvalidAddr(s) => write!(f, "{} is neither an IP nor a socket address", s),
            ConfigError::UnsupportedAddrs(s) => write!(f, "none of the IPs ({}) are public IPs", s),
            ConfigError::MissingArgument(s) => write!(f, "{} is missing its following argument", s),
            ConfigError::UnsupportedOption(opt, flag) => {
                write!(f, "{} is not supported for {}", opt, flag)
            }
            ConfigError::JustPrintUsage => write!(f, ""),
        }
    }
}

const DEFAULT_DNS_PORT: u16 = if cfg!(debug_assertions) { 5053 } else { 53 };
const DEFAULT_ADDR_V4: SocketAddr = if cfg!(debug_assertions) {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), DEFAULT_DNS_PORT)
} else {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DEFAULT_DNS_PORT)
};
const DEFAULT_ADDR_V6: SocketAddr = if cfg!(debug_assertions) {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        DEFAULT_DNS_PORT,
    )
} else {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        DEFAULT_DNS_PORT,
    )
};

pub fn parse_config() -> Result<Config, ConfigError> {
    let mut config = Config {
        http_port: std::env::var("CERTBOT_DNS_CHAMP_HTTP_PORT")
            .ok()
            .and_then(|s| u16::from_str(&s).ok())
            .unwrap_or(8053),
        dns_addr_4: std::env::var("CERTBOT_DNS_CHAMP_DNS_ADDR")
            .ok()
            .and_then(|s| parse_socketish(&s)),
        dns_addr_6: std::env::var("CERTBOT_DNS_CHAMP_DNS_ADDR_6")
            .ok()
            .and_then(|s| parse_socketish(&s)),
        require_v6: true,
        server_ips: ServerIps { v4: None, v6: None },
        loglevel: std::env::var("CERTBOT_DNS_CHAMP_LOG_LEVEL")
            .ok()
            .and_then(|s| Level::from_str(&s).ok())
            .unwrap_or(Level::Info),
        logformat: std::env::var("CERTBOT_DNS_CHAMP_LOG_FORMAT")
            .ok()
            .and_then(|s| LogFormat::from_str(&s))
            .unwrap_or(LogFormat::default()),
        username: std::env::var("CERTBOT_DNS_CHAMP_USERNAME").ok(),
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
                Some(s) => match parse_addrs(&s) {
                    Ok(addrs) => {
                        for addr in addrs {
                            if addr.is_ipv4() {
                                config.dns_addr_4 = Some(addr);
                            } else if addr.is_ipv6() {
                                config.dns_addr_6 = Some(addr);
                            }
                        }
                    }
                    Err(InvalidDnsAddrs::InvalidAddr(addr)) => {
                        return Err(ConfigError::InvalidAddr(addr.to_string()));
                    }
                    Err(InvalidDnsAddrs::UnsupportedAddrs(s)) => {
                        return Err(ConfigError::UnsupportedAddrs(s.to_string()));
                    }
                },
                None => return Err(ConfigError::MissingArgument(flag.to_string())),
            },
            flag @ "-l" | flag @ "--log-level" => {
                config.loglevel = match args.next().as_deref() {
                    Some(s) => Level::from_str(s).map_err(|_| {
                        ConfigError::UnsupportedOption(s.to_string(), flag.to_string())
                    })?,
                    None => return Err(ConfigError::MissingArgument(flag.to_string())),
                };
            }
            flag @ "--log-format" => {
                config.logformat = match args.next().as_deref() {
                    Some(s) => LogFormat::from_str(s).ok_or(ConfigError::UnsupportedOption(
                        s.to_string(),
                        flag.to_string(),
                    ))?,
                    None => return Err(ConfigError::MissingArgument(flag.to_string())),
                }
            }
            flag @ "-u" | flag @ "--username" => {
                config.username = match args.next() {
                    Some(u) => Some(u),
                    None => return Err(ConfigError::MissingArgument(flag.to_string())),
                }
            }
            "-h" | "--help" => {
                return Err(ConfigError::JustPrintUsage);
            }
            _ => {}
        }
    }

    if config.dns_addr_4.is_none() && config.dns_addr_6.is_none() {
        config.dns_addr_4 = Some(DEFAULT_ADDR_V4);
        config.dns_addr_6 = Some(DEFAULT_ADDR_V6);
        config.require_v6 = false;
    }

    if let Some(addr) = config.dns_addr_4 {
        if let IpAddr::V4(ip) = addr.ip() {
            if !ip.is_unspecified() {
                config.server_ips.v4 = Some(ip);
            }
        }
    }

    if let Some(addr) = config.dns_addr_6 {
        if let IpAddr::V6(ip) = addr.ip() {
            if !ip.is_unspecified() {
                config.server_ips.v6 = Some(ip);
            }
        }
    }

    Ok(config)
}

enum InvalidDnsAddrs<'a> {
    InvalidAddr(&'a str),
    UnsupportedAddrs(&'a str),
}

/// Parses a list of space-separated socket addresses or IP addresses.
///
/// If a substring is an IP address and not a socket address, it is
/// given the default port 53 in release, or 5053 in debug.
///
/// This function filters out private IPs in the 10.0.0.0/8 range, so
/// that a user can dump the output of `hostname -I` into the `--dns-addr`
/// argument, and listen on whichever non-private IP addresses are there.
/// Passing a single address per `--dns-addr` argument explicitly disables
/// this filtering.
fn parse_addrs<'a>(s: &'a str) -> Result<Vec<SocketAddr>, InvalidDnsAddrs<'a>> {
    let mut addrs = Vec::with_capacity(2);
    for maybe_addr in s.split(' ') {
        if maybe_addr.is_empty() {
            continue;
        }

        match parse_socketish(maybe_addr) {
            Some(addr) => addrs.push(addr),
            None => return Err(InvalidDnsAddrs::InvalidAddr(maybe_addr)),
        }
    }

    if addrs.len() > 1 {
        addrs.retain(|addr| match addr.ip() {
            IpAddr::V4(ip) => !ip.is_private(),
            IpAddr::V6(_) => true,
        });
    }

    if addrs.is_empty() {
        return Err(InvalidDnsAddrs::UnsupportedAddrs(s));
    }
    Ok(addrs)
}

fn parse_socketish(maybe_addr: &str) -> Option<SocketAddr> {
    maybe_addr
        .parse::<SocketAddr>()
        .or_else(|_| {
            maybe_addr
                .parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, DEFAULT_DNS_PORT))
        })
        .ok()
}
