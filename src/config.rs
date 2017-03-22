use std::fmt;
use std::rc::Rc;
use std::net::SocketAddr;
use std::net::AddrParseError;
use std::error::Error;
use std::cell::RefCell;
use toml;

pub type ConfigResult<T> = Result<T, ConfigError>;

lazy_static! {
    static ref DEFAULT_DNS_SERVERS: StaticWrapper<Rc<Vec<SocketAddr>>> = StaticWrapper(Rc::new(vec![
        "8.8.8.8:53".parse().unwrap(),
        "8.8.4.4:53".parse().unwrap(),
    ]));
    static ref DEFAULT_TIMEOUT_RETRIES: u32 = 10;
    static ref DEFAULT_TASK_BUFFER_SIZE: usize = 100;

    pub static ref CONFIG: StaticWrapper<Config> = StaticWrapper(Config::new());
}

macro_rules! uncell {
    ($expr:expr) => (*$expr.borrow())
}

macro_rules! uncell_mut {
    ($expr:expr) => (*$expr.borrow_mut())
}


#[derive(Clone, Debug)]
pub struct Config {
    dns_servers: RefCell<Rc<Vec<SocketAddr>>>,
    timeout_retries: RefCell<u32>,
    task_buffer_size: RefCell<usize>
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dns_servers: RefCell::new(DEFAULT_DNS_SERVERS.clone()),
            timeout_retries: RefCell::new(*DEFAULT_TIMEOUT_RETRIES),
            task_buffer_size: RefCell::new(*DEFAULT_TASK_BUFFER_SIZE),
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn dns_servers(&self) -> Rc<Vec<SocketAddr>> {
        uncell!(self.dns_servers).clone()
    }

    pub fn timeout_retries(&self) -> u32 {
        uncell!(self.timeout_retries)
    }

    pub fn task_buffer_size(&self) -> usize {
        uncell!(self.task_buffer_size)
    }

    pub fn parse(&self, string: &str) -> ConfigResult<()> {
        let mut cfg_fmt: ConfigFormat = toml::from_str(string)?;

        if let Some(mut dns) = cfg_fmt.dns.take() {
            let mut dns_servers = Vec::new();
            
            for addr in &mut dns {
                if !addr.contains(":") { addr.push_str(":53") }
                dns_servers.push(addr.parse()?);
            }

            uncell_mut!(self.dns_servers) = Rc::new(dns_servers);
        }

        if let Some(retry) = cfg_fmt.retry {
            uncell_mut!(self.timeout_retries) = retry;
        }
    
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct ConfigFormat {
    dns: Option<Vec<String>>,
    retry: Option<u32>,
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

