use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::str;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;

use futures::sync::oneshot;
use futures::sync::mpsc;
use futures::Future;
use futures::BoxFuture;
use futures::future::{err, ok};
use futures_cpupool::CpuPool;
use futures::Sink;
use futures::future;
use futures::stream;
use futures::Stream;
use futures::stream::once;
use futures::IntoFuture;

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
use trust_dns::error::ClientErrorKind;

pub struct TrustDNSResolver {
    dns_server_addrs: Vec<SocketAddr>,
    last_chosen: RefCell<usize>,
    loop_handle: Handle,
    done_tx: mpsc::Sender<()>,
}

use std::time::Duration;

impl TrustDNSResolver {
    pub fn new(dns_server_addrs: Vec<SocketAddr>, loop_handle: Handle, done_tx: mpsc::Sender<()>) -> Self {
        TrustDNSResolver {
            dns_server_addrs: dns_server_addrs,
            last_chosen: RefCell::new(0),
            loop_handle: loop_handle,
            done_tx: done_tx
        }
    }
}

impl TrustDNSResolver {
    fn next_namesrv(&self) -> SocketAddr {
        let idx = (*self.last_chosen.borrow()) % self.dns_server_addrs.len();
        (*self.last_chosen.borrow_mut()) += 1;
        self.dns_server_addrs[idx]
    }

    fn client_with_namesrv(addr: SocketAddr, loop_handle: Handle) -> BasicClientHandle {
        let (stream, stream_handle) = TcpClientStream::new(
            addr, loop_handle.clone()
        );

        ClientFuture::new(
            stream,
            stream_handle,
            loop_handle,
            None
        )
    }

    fn new_client(&self) -> BasicClientHandle {
        Self::client_with_namesrv(self.next_namesrv(), self.loop_handle.clone())
    }
    
    pub fn resolve(&self, host: &str) -> Box<Future<Item=Option<Vec<DnsData>>, Error=ResolverError>> {
        // @TODO concider adding AAAAA (ipv6) records
        let done_tx = self.done_tx.clone();
        let client = self.new_client();

        let future = Self::resolve_retry3(
            client,
            Name::parse(host, Some(&Name::root())).unwrap(), 
            DNSClass::IN, 
            RecordType::A, 
        ).map(|x| opt_msg_to_vec_dnsdata(x))
         .map(|x| report_if_some(x, done_tx));

        Box::new(future)
    }

    pub fn reverse_resolve(&mut self, ip: &str) -> Box<Future<Item=Option<Vec<DnsData>>, Error=ResolverError>> {
        let labels = ip.split('.').map(str::to_owned).collect();
        let done_tx = self.done_tx.clone();
        let (tx, rx) = mpsc::channel(16);

        Self::recurse_nameserver(
            self.loop_handle.clone(),
            self.new_client(),
            NS::Known(self.next_namesrv()),
            Name::with_labels(labels),
            DNSClass::IN, 
            RecordType::PTR,
            tx
        );
/*
        let first_answer = rx.take(1).into_future().map(|(message, _)| {
            message
        });

        let rx_future = first_answer.map(|msg| {
            let dnsdata = opt_msg_to_vec_dnsdata(msg);
            report_if_some(dnsdata, done_tx)
        }).or_else(|_| {
            Ok(None)   
        });

*/
        let rx_future = rx.collect().map(|vec| {
           println!("{:?}", vec); 
           Some(vec![])
        }).map_err(|_| ResolverError::FuturesSendError);

        Box::new(rx_future)
    }

    fn recurse_nameserver(loop_handle: Handle, resolve_client: BasicClientHandle, nameserver: NS, name: Name, query_class: DNSClass, query_type: RecordType, message_tx: mpsc::Sender<Message>) {
        println!("Resolving {:?}. ns: {:?}", name, nameserver);
        let recurse_resolve_client = resolve_client.clone();
        let recurse_loop_handle = loop_handle.clone();
        let recurse_down = |ns_addr: Box<Future<Item=Option<SocketAddr>, Error=ResolverError>>| {
            let future = ns_addr.and_then(move |ns| {
                ns.map(|ns| {
                    Self::resolve_retry3(
                        Self::client_with_namesrv(ns, recurse_loop_handle.clone()),
                        name.clone(),
                        query_class, 
                        query_type
                    ).and_then(move |message| {
                        if let Some(msg) = message {
                            println!("{:?}", msg);
                            if msg.answers().is_empty() {
                                for nameserver in msg.name_servers().iter().map(|record| record.name().to_string()) {
                                    Self::recurse_nameserver(
                                        recurse_loop_handle.clone(),
                                        recurse_resolve_client.clone(),
                                        NS::Unknown(nameserver),
                                        name.clone(), 
                                        query_class, 
                                        query_type, 
                                        message_tx.clone()
                                    );
                                }
                            } else {
                                // Ignore result because multiple tasks can write to oneshot
                                // while wee need only single result, so they can just fail to send
                                message_tx.send(msg).wait().unwrap();
                            }
                        }
                        Ok(())
                    })
                });
                Ok(())
            });

            let future = future.map_err(|_| ());
                
            loop_handle.spawn(future);
        };

        match nameserver {
            NS::Known(addr) => recurse_down(box ok(Some(addr))),
            NS::Unknown(domain) => {
                let addr = Self::resolve_retry3(
                    resolve_client,
                    Name::parse(&domain, Some(&Name::root())).unwrap(), 
                    DNSClass::IN, 
                    RecordType::A, 
                ).map(|msg| opt_msg_to_vec_dnsdata(msg)
                    .and_then(|dnsdata|     dnsdata.into_iter().nth(0))
                    .and_then(|mut dnsdata| dnsdata.take_ip())
                    .map(|ip| ip.parse::<SocketAddr>().unwrap()) 
                );
                recurse_down(box addr);
            }
        };
    }

    fn resolve_retry3(client: BasicClientHandle, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Option<Message>, Error=ResolverError>>
    {
        macro_rules! map_err {
            ($future:expr) => (
                $future.map_err(|e| {
                    ResolverError::DnsClientError(e)
                })
            )
        }
    
        Box::new( 
                              Self::_resolve(client.clone(), name.clone(), query_class, query_type)
            .or_else(move |_| Self::_resolve(client.clone(), name.clone(), query_class, query_type)
            .or_else(move |_| Self::_resolve(client,         name,         query_class, query_type)
            .or_else(move |error| match *error.kind() {
                ClientErrorKind::Timeout      => Ok(None),
                ClientErrorKind::Canceled(..) => Ok(None),
                _ => Err(error)
            })
            .map_err(|e| {
                ResolverError::DnsClientError(e)
            })))
        )
    }

    fn _resolve(mut client: BasicClientHandle, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Option<Message>, Error=ClientError>>
    {
        Box::new(
            client.query(
                name,
                query_class,
                query_type
            ).map(Option::from)
        )
    }
}

#[derive(Debug)]
pub struct DnsData {
    name: Option<String>,
    ipv4: Option<String>,
    ipv6: Option<String>,
}

use trust_dns::rr::RData::{A, AAAA};

impl<'a> From<&'a Record> for DnsData {
    fn from(record: &'a Record) -> DnsData {
        let name = Some(record.name().to_string());
        let ipv4 = if let &A(ip)    = record.rdata() {Some(ip.to_string())} else {None};
        let ipv6 = if let &AAAA(ip) = record.rdata() {Some(ip.to_string())} else {None};
        DnsData {
            name: name,
            ipv4: ipv4,
            ipv6: ipv6
        }
    }
}

fn opt_msg_to_vec_dnsdata(mut msg: Option<Message>) -> Option<Vec<DnsData>> {
    msg.take().map(|msg| {
        msg_to_vec_dnsdata(msg)
    })
}

fn msg_to_vec_dnsdata(msg: Message) -> Vec<DnsData> {
    msg.answers().iter() 
       .map(|record| {
           DnsData::from(record)
       })
       .collect()
}

fn report_if_some<T, E: Default>(data: Option<T>, done_tx: mpsc::Sender<E>) -> Option<T> {
    if data.is_some() {
        done_tx.send(E::default()).wait().unwrap();
    }
    data
}

impl DnsData {
    pub fn take_name(&mut self) -> Option<String> {
        self.name.take()
    }

    pub fn take_ip(&mut self) -> Option<String> {
        self.ipv4.take().or(self.ipv6.take())
    }
}

#[derive(Debug)]
enum NS {
    Known(SocketAddr),
    Unknown(String)
}

