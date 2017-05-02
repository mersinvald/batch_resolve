use std::fmt;
use std::sync::{Arc, RwLock};
use std::net::AddrParseError;
use std::error::Error;
use toml;

use std::net::SocketAddr;

pub type ConfigResult<T> = Result<T, ConfigError>;

lazy_static! {
    static ref DEFAULT_DNS_SERVERS: Vec<SocketAddr> = vec![
        "8.8.8.8:53".parse().unwrap(),
        "8.8.4.4:53".parse().unwrap(),
    ];

    static ref DEFAULT_TIMEOUT_RETRIES: u32 = 10;
    static ref DEFAULT_QPS: u32 = 5000;

    pub static ref CONFIG: Arc<RwLock<Config>> = Arc::new(RwLock::new(Config::new()));
}

#[derive(Debug)]
pub struct Config {
    dns_list: Vec<SocketAddr>,
    qps: u32,
    timeout_retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dns_list: DEFAULT_DNS_SERVERS.clone(),
            qps: *DEFAULT_QPS,
            timeout_retries: *DEFAULT_TIMEOUT_RETRIES,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn timeout_retries(&self) -> u32 {
        self.timeout_retries
    }

    pub fn qps(&self) -> u32 {
        self.qps
    }

    pub fn dns_list(&self) -> &[SocketAddr] {
        &self.dns_list
    }

    pub fn parse(&mut self, string: &str) -> ConfigResult<()> {
        #[derive(Serialize, Deserialize, Debug)]
        struct Config {
            dns: Option<Vec<String>>,
            retry: Option<u32>,
            queries_per_second: Option<u32>,
        }

        let mut cfg_fmt: Config = toml::from_str(string)?;

        if let Some(mut dns_fmt_vec) = cfg_fmt.dns.take() {
            let mut dns_servers = Vec::new();

            for dns in &mut dns_fmt_vec {
                if !dns.contains(":") {
                    dns.push_str(":53")
                }
                dns_servers.push(dns.parse()?);
            }

            debug!("{:?}", dns_servers);

            self.dns_list = dns_servers;
        }

        if let Some(retry) = cfg_fmt.retry {
            self.timeout_retries = retry;
        }

        if let Some(qps) = cfg_fmt.queries_per_second {
            self.qps = qps;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    AddrParseError(AddrParseError),
    TomlParseError(toml::de::Error),
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        match *self {
            ConfigError::AddrParseError(ref err) => err.description(),
            ConfigError::TomlParseError(ref err) => err.description(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.description())
    }
}

impl From<AddrParseError> for ConfigError {
    fn from(err: AddrParseError) -> Self {
        ConfigError::AddrParseError(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        ConfigError::TomlParseError(err)
    }
}
