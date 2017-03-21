use std::rc::Rc;
use std::net::SocketAddr;

lazy_static! {
    static ref DEFAULT_DNS_SERVERS: StaticWrapper<Rc<Vec<SocketAddr>>> = StaticWrapper(Rc::new(vec![
        "8.8.8.8:53".parse().unwrap(),
        "8.8.4.4:53".parse().unwrap(),
    ]));
    static ref DEFAULT_TIMEOUT_RETRIES: u32 = 10;
    static ref DEFAULT_TASK_BUFFER_SIZE: usize = 100;

    pub static ref CONFIG: StaticWrapper<Config> = StaticWrapper(Config::default());
}

#[derive(Default)]
pub struct Config {
    dns_servers: Option<Rc<Vec<SocketAddr>>>,
    timeout_retries: Option<u32>,
    task_buffer_size: Option<usize>
}

impl Config {
    pub fn new() -> Self {
        Config::default()
    }

    pub fn dns_servers<I>(mut self, servers: I) -> Self 
        where I: Into<Rc<Vec<SocketAddr>>>
    {
        self.dns_servers = Some(servers.into());
        self    
    }

    pub fn timeout_retries(mut self, count: u32) -> Self {
        self.timeout_retries = Some(count);
        self
    }

    pub fn task_buffer_size(mut self, size: usize) -> Self {
        self.task_buffer_size = Some(size);
        self
    }

    pub fn get_dns_servers(&self) -> Rc<Vec<SocketAddr>> {
        self.dns_servers.as_ref().unwrap_or(&DEFAULT_DNS_SERVERS).clone()
    }

    pub fn get_timeout_retries(&self) -> u32 {
        self.timeout_retries.unwrap_or(*DEFAULT_TIMEOUT_RETRIES)
    }

    pub fn get_task_buffer_size(&self) -> usize {
        self.task_buffer_size.unwrap_or(*DEFAULT_TASK_BUFFER_SIZE)
    }
}

pub struct StaticWrapper<T>(T);
unsafe impl<T> Send for StaticWrapper<T> {}
unsafe impl<T> Sync for StaticWrapper<T> {}

use std::ops::{Deref, DerefMut};

impl<T> Deref for StaticWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for StaticWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}


