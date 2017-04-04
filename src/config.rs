use std::fmt;
use std::rc::Rc;
use std::net::AddrParseError;
use std::error::Error;
use std::cell::RefCell;
use toml;

use resolve::dns::*;
use resolve::dns;

pub type ConfigResult<T> = Result<T, ConfigError>;

lazy_static! {
    static ref DEFAULT_DNS_SERVERS: StaticWrapper<Vec<Dns>> = StaticWrapper(vec![
        Dns::new("8.8.8.8:53".parse().unwrap(), 500),
        Dns::new("8.8.4.4:53".parse().unwrap(), 500),
    ]);
    static ref DEFAULT_TIMEOUT_RETRIES: u32 = 10;

    pub static ref CONFIG: StaticWrapper<Config> = StaticWrapper(Config::new());
}

#[derive(Debug)]
pub struct Config {
    dns_store: RefCell<Rc<DnsStore>>,
    timeout_retries: RefCell<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dns_store: RefCell::new(Rc::new(DnsStore::new(DEFAULT_DNS_SERVERS.clone()))),
            timeout_retries: RefCell::new(*DEFAULT_TIMEOUT_RETRIES),
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn dns_store(&self) -> Rc<DnsStore> {
        uncell!(self.dns_store).clone()
    }

    pub fn timeout_retries(&self) -> u32 {
        uncell!(self.timeout_retries)
    }

    pub fn parse(&self, string: &str) -> ConfigResult<()> {
        #[derive(Serialize, Deserialize, Debug)]
        struct Dns {
            addr: String,
            qps:  Option<u32>
        }

        #[derive(Serialize, Deserialize, Debug)]
        struct Config {
            dns: Option<Vec<Dns>>,
            retry: Option<u32>,
            task_buffer_size: Option<usize>,
        }

        let mut cfg_fmt: Config = toml::from_str(string)?;

        if let Some(mut dns_fmt_vec) = cfg_fmt.dns.take() {
            let mut dns_servers = Vec::new();

            for dns in &mut dns_fmt_vec {
                if !dns.addr.contains(":") {
                    dns.addr.push_str(":53")
                }
                dns_servers.push(
                    dns::Dns::new(dns.addr.parse()?, 
                             dns.qps.unwrap_or(300)
                    )
                );
            }

            debug!("{:?}", dns_servers);

            uncell_mut!(self.dns_store) = Rc::new(dns::DnsStore::new(dns_servers));
        }

        if let Some(retry) = cfg_fmt.retry {
            uncell_mut!(self.timeout_retries) = retry;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    AddrParseError(AddrParseError),
    TomlParseError(toml::de::Error)
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        match *self {
            ConfigError::AddrParseError(ref err) => err.description(),
            ConfigError::TomlParseError(ref err) => err.description()
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

#[derive(Debug)]
pub struct StaticWrapper<T>(T);
unsafe impl<T> Send for StaticWrapper<T> {}
unsafe impl<T> Sync for StaticWrapper<T> {}

use std::ops::Deref;

impl<T> Deref for StaticWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

