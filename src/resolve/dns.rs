use std::rc::Rc;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::time::Instant;
use std::borrow::Borrow;

use futures::Stream;
use futures::Poll;
use futures::Async;

use resolve::error::*;

#[derive(Copy, Clone, Debug, new)]
pub struct Dns {
    pub addr: SocketAddr,
    pub qps: u32,
}

#[derive(Debug, Clone)]
pub struct CountingDns {
    addr:    SocketAddr,
    max_qps: u32,
    qps:     u32,
    instant: Instant,
}

impl<D> From<D> for CountingDns 
    where D: Borrow<Dns>
{
    fn from(dns: D) -> Self {
        let dns = dns.borrow();
        CountingDns {
            addr: dns.addr,
            max_qps: dns.qps,
            qps: 0,
            instant: Instant::now()
        }
    }
}

impl<D> From<D> for Dns 
    where D: Borrow<CountingDns> 
{
    fn from(dns: D) -> Self {
        let dns = dns.borrow();
        Dns {
            addr: dns.addr,
            qps: dns.max_qps,
        }
    }
}   

impl CountingDns {
    fn get_addr(&mut self) -> Option<SocketAddr> {
        let elapsed = self.instant.elapsed();
        let addr = if elapsed.as_secs() < 1 {
            if self.qps < self.max_qps {
                self.qps += 1;
                Some(self.addr)
            } else {
                None
            }
        } else {
            self.instant = Instant::now();
            self.qps = 1;
            Some(self.addr)
        };
        addr
    }
}

#[derive(Debug)]
pub struct DnsStore {
    servers: Vec<RefCell<CountingDns>>
}

impl DnsStore {
    pub fn new<T>(servers: T) -> Self 
        where T: Borrow<Vec<Dns>>
    {
        let servers = servers.borrow();
        let counting = servers.iter()
            .map(CountingDns::from)
            .map(RefCell::from)
            .collect();
        DnsStore {
            servers: counting
        }
    }

    pub fn get_dns(&self) -> Option<SocketAddr> {
        for server in &self.servers {
            match uncell_mut!(server).get_addr() {
                Some(addr) => return Some(addr),
                None => (),
            }
        }

        None
    }

    pub fn get_hosts(&self) -> Vec<Dns> {
        self.servers.iter().map(|server| {
            uncell!(server).clone().into()
        }).collect()
    }

    pub fn overall_qps(&self) -> usize {
        self.servers.iter()
                    .map(|dns| uncell!(dns).max_qps as usize)
                    .sum()
    }

    pub fn average_qps(&self) -> usize {
        self.overall_qps() / self.servers.len()
    }
}

#[derive(Debug, Clone)]
pub struct DnsStream {
    store: Rc<DnsStore>,
}

impl Stream for DnsStream {
    type Item = SocketAddr;
    type Error = ResolverError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.store.get_dns() {
            Some(dns) => Ok(Async::Ready(Some(dns))),
            None => Ok(Async::NotReady)
        }
    }
}

pub fn dns_stream(store: Rc<DnsStore>) -> DnsStream {
    DnsStream {
        store: store
    }
}