use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::str;

use futures::Future;
use futures::BoxFuture;
use futures_cpupool::CpuPool;

use ::resolver_sys::*;
use std::clone::Clone;

error_chain! {
    errors {
        Again 
        OutOfMemory
        Fail
    }

    foreign_links {
        Io(::std::io::Error);
        ClientError(::trust_dns::error::ClientError);
    }
}


/// The Resolver trait represents an object capable of
/// resolving host names into IP addresses.
pub trait Resolver {
    /// Given a host name, this function returns a Future which
    /// will eventually resolve into a list of IP addresses.
    fn resolve(&self, host: &str) -> BoxFuture<Option<Vec<IpAddr>>, Error>;

    /// Given an ip address, this funtion returns a Future which
    /// will eventually reverse resolve into a domain name
    fn reverse_resolve(&self, ip: IpAddr) -> BoxFuture<Option<String>, Error>;
}

/// A resolver based on a thread pool.
///
/// This resolver uses the `ToSocketAddrs` trait inside
/// a thread to provide non-blocking address resolving.
#[derive(Clone)]
pub struct CpuPoolResolver {
    pool: CpuPool,
}

impl CpuPoolResolver {
    /// Create a new CpuPoolResolver with the given number of threads.
    pub fn new(num_threads: usize) -> Self {
        CpuPoolResolver {
            pool: CpuPool::new(num_threads),
        }
    }
}

impl Resolver for CpuPoolResolver {
    fn resolve(&self, host: &str) -> BoxFuture<Option<Vec<IpAddr>>, Error> {
        let host = format!("{}:0", host);
        self.pool.spawn_fn(move || {
            match host[..].to_socket_addrs() {
                Ok(it) => Ok(Some(it.map(|s| s.ip()).collect())),
                Err(..) => Ok(None),
            }
        }).boxed()
    }

    fn reverse_resolve(&self, ip: IpAddr) -> BoxFuture<Option<String>, Error> {
        self.pool.spawn_fn(move || {
            match getnameinfo(&ip) {
                Ok(hostname) => Ok(Some(hostname)),
                Err(..) => Ok(None)
            }
        }).boxed()
    }
}

use std::net::SocketAddr;
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::tcp::TcpClientStream;
use trust_dns::error::ClientError;
use trust_dns::rr::domain::Name;
use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::dns_class::DNSClass;
use trust_dns::op::message::Message;
use tokio_core::reactor::Handle;

pub struct TrustDNSResolver {
    client: BasicClientHandle,
}

impl TrustDNSResolver {
    pub fn new(dns_server_addr: SocketAddr, loop_handle: Handle) -> Self {
        let (stream, stream_handle) = TcpClientStream::new(dns_server_addr, loop_handle.clone());
        let client_handle = ClientFuture::new(
            stream,
            stream_handle,
            loop_handle,
            None
        );

        TrustDNSResolver {
            client: client_handle
        }
    }
}

impl TrustDNSResolver {
    pub fn resolve(&mut self, host: &str) -> Box<Future<Item=Message, Error=ClientError>> {
        // @TODO add AAAAA (ipv6) records if needed
        let name = Name::parse(host, None).unwrap();
        let query_class = DNSClass::ANY;
        let query_type = RecordType::A;
        self.client.query(
            name,
            query_class,
            query_type
        )
    }

    pub fn reverse_resolve(&mut self, ip: &str) -> Box<Future<Item=Message, Error=ClientError>> {
        let name = Name::parse(ip, None).unwrap();
        let query_class = DNSClass::ANY;
        let query_type = RecordType::PTR;
        self.client.query(
            name,
            query_class,
            query_type
        )
    }
}