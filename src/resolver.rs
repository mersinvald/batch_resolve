use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::str;

use futures::Future;
use futures::BoxFuture;
use futures_cpupool::CpuPool;

use error::*;
use std::clone::Clone;

use std::net::SocketAddr;
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::tcp::TcpClientStream;
use trust_dns::error::ClientError;
use trust_dns::rr::domain::Name;
use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::dns_class::DNSClass;
use trust_dns::rr::resource::Record;
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
    pub fn resolve(&mut self, host: &str) -> Box<Future<Item=Vec<String>, Error=ResolverError>> {
        // @TODO concider adding AAAAA (ipv6) records
        self._resolve(
            Name::parse(host, None).unwrap(), 
            DNSClass::ANY, 
            RecordType::A,    
        )
    }

    pub fn reverse_resolve(&mut self, ip: &str) -> Box<Future<Item=Vec<String>, Error=ResolverError>> {
        self._resolve(
            Name::parse(ip, None).unwrap(), 
            DNSClass::ANY, 
            RecordType::PTR,    
        )
    }

    fn _resolve(&mut self, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Vec<String>, Error=ResolverError>>
    {
        Box::new(
            self.client.query(
                name,
                query_class,
                query_type
            ).map_err(|err| {
                ResolverError::DnsClientError(err)
            }).map(|message| {
                message.answers().iter()
                       .map(Record::name)
                       .map(Name::to_string)
                       .collect()
            })
        )
    }
}