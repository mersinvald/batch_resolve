use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::str;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use std::result;

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
use futures::future::Loop;

use error::*;
use std::clone::Clone;

use std::net::SocketAddr;
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::tcp::TcpClientStream;
use trust_dns::udp::UdpClientStream;
use trust_dns::error::ClientError;
use trust_dns::rr::domain::Name;
use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::dns_class::DNSClass;
use trust_dns::rr::resource::Record;
use trust_dns::op::message::Message;
use tokio_core::reactor::Handle;
use trust_dns::error::ClientErrorKind;

fn make_client(loop_handle: Handle, name_server: SocketAddr) -> BasicClientHandle {
    let (stream, stream_handle) = UdpClientStream::new(
        name_server, loop_handle.clone()
    );

    ClientFuture::new(
        stream,
        stream_handle,
        loop_handle,
        None
    )
}

trait ClientFactory {
    fn new_client(&self) -> BasicClientHandle;
}

struct FixedClientFactory {
    loop_handle: Handle,
    name_server: SocketAddr,
}

impl FixedClientFactory {
    pub fn new(loop_handle: Handle, name_server: SocketAddr) -> FixedClientFactory {
        FixedClientFactory {
            loop_handle: loop_handle,
            name_server: name_server,
        }
    }
}

impl ClientFactory for FixedClientFactory {
    fn new_client(&self) -> BasicClientHandle {
        make_client(self.loop_handle.clone(), self.name_server)
    }
}

struct LevellingClientFactory {
    dns_server_addrs: Vec<SocketAddr>,
    last_chosen: RefCell<usize>,
    loop_handle: Handle,
}

impl LevellingClientFactory {
    pub fn new(dns_server_addrs: Vec<SocketAddr>, loop_handle: Handle) -> LevellingClientFactory {
        LevellingClientFactory {
            dns_server_addrs: dns_server_addrs,
            last_chosen: RefCell::from(0),
            loop_handle: loop_handle,
        }
    }

    pub fn next_namesrv(&self) -> SocketAddr {
        let idx = (*self.last_chosen.borrow()) % self.dns_server_addrs.len();
        (*self.last_chosen.borrow_mut()) += 1;
        self.dns_server_addrs[idx]
    }
}

impl ClientFactory for LevellingClientFactory {
    fn new_client(&self) -> BasicClientHandle {
        make_client(self.loop_handle.clone(), self.next_namesrv())
    }
}

pub struct TrustDNSResolver {
    loop_handle: Handle,
    client_factory: Rc<LevellingClientFactory>,
    done_tx: mpsc::Sender<ResolveStatus>,
}

impl TrustDNSResolver {
    pub fn new(dns_server_addrs: Vec<SocketAddr>, loop_handle: Handle, done_tx: mpsc::Sender<ResolveStatus>) -> Self {
        TrustDNSResolver {
            loop_handle: loop_handle.clone(),
            client_factory: Rc::new(LevellingClientFactory::new(
                dns_server_addrs,
                loop_handle,
            )),
            done_tx: done_tx
        }
    }
}

impl TrustDNSResolver {
    pub fn resolve(&self, host: &str) -> Box<Future<Item=Option<Vec<DnsData>>, Error=ResolverError>> {
        // @TODO concider adding AAAAA (ipv6) records
        let done_tx = self.done_tx.clone();
        let future = Self::resolve_retry3(
            self.client_factory.clone(),
            Name::parse(host, Some(&Name::root())).unwrap(), 
            DNSClass::IN, 
            RecordType::A, 
        ).map(|x| opt_msg_to_vec_dnsdata(x))
         .and_then(|x| Ok(report_status(x, done_tx)));

        Box::new(future)
    }

    pub fn reverse_resolve(&self, ip: &str) -> Box<Future<Item=Option<Vec<DnsData>>, Error=ResolverError>> {
        let mut labels = ip.split('.').map(str::to_owned).collect::<Vec<_>>();
        labels.reverse();

        let done_tx = self.done_tx.clone();

        let future = self.recurse_ptr(
            Name::with_labels(labels).label("in-addr").label("arpa"),
            DNSClass::IN, 
            RecordType::PTR,
        ).and_then(|x| Ok(report_status(x, done_tx)));

        Box::new(future)
    }

    fn recurse_ptr(&self, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Option<Vec<DnsData>>, Error=ResolverError>>
    {
        let state = State {
            handle: self.loop_handle.clone(),
            client_factory: self.client_factory.clone(),
            ns: vec![NS::Known(self.client_factory.next_namesrv())],
            result: vec![]
        };

        let resolve_loop = future::loop_fn(state, move |mut state| {
            Self::resolve_with_ns(
                state.handle.clone(),
                state.client_factory.clone(),
                state.ns.pop().unwrap(),
                name.clone(), query_class, query_type
            ).map(move |message| {
                trace!("Received DNS message: {:?}", message);
                message.map(|mut msg| {
                    state.ns.extend(msg.take_name_servers().iter()
                            .filter(|ns| ns.name().num_labels() != 0)
                            .map(|ns|   ns.name())
                            .map(|name| NS::Unknown(name.to_string())));
                    state.result.extend(msg_to_vec_dnsdata(msg));
                });
                state
            })
            .and_then(|state| {
                if !state.result.is_empty() || state.ns.is_empty() {
                    Ok(Loop::Break(state))
                } else {
                    Ok(Loop::Continue(state))
                }
            })
        });

        Box::new(resolve_loop.map(|state| if state.result.is_empty() {
            None
        } else {
            Some(state.result)
        }))
    }

    fn resolve_with_ns(loop_handle: Handle, client_factory: Rc<ClientFactory>, nameserver: NS, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Option<Message>, Error=ResolverError>>
    {
        debug!("Resolving {:?} with nameserver {:?}", name.to_string(), nameserver.to_string());
        let ns_resolve: Box<Future<Item=Option<SocketAddr>, Error=ResolverError>> = match nameserver {
            NS::Known(addr) => box ok(Some(addr)),
            NS::Unknown(domain) => {
                box Self::resolve_retry3(
                    client_factory.clone(),
                    Name::parse(&domain, Some(&Name::root())).unwrap(), 
                    DNSClass::IN, 
                    RecordType::A, 
                ).map(|msg| opt_msg_to_vec_dnsdata(msg)
                    .and_then(|dnsdata|     dnsdata.into_iter().nth(0))
                    .and_then(|mut dnsdata| dnsdata.take_ip())
                    .map     (|mut ip| { ip.push_str(":53"); ip} )
                    .and_then(|ip| ip.parse::<SocketAddr>().map_err(|e| {
                        warn!("Invalid IP({:?}): {:?}", ip, e);
                        e
                    }).ok()) 
                )
            }
        };

        
        let future = ns_resolve.and_then(move |ns| match ns {
            None => box ok(None),
            Some(ns) => 
                Self::resolve_retry3(
                    Rc::new(FixedClientFactory::new(loop_handle, ns)),
                    name.clone(),
                    query_class, 
                    query_type, 
                )
        });

        Box::new(future)
    }

    // @TODO Do something with this mad-caffeine-overdose shit
    fn resolve_retry3(client_factory: Rc<ClientFactory>, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Option<Message>, Error=ResolverError>>
    {
        let state = Rc::new(RefCell::new((3, None)));
        let name_copy = name.clone();

        let retry_loop = future::loop_fn(state, move |state| {
            let success_state = state.clone();
            Self::_resolve(client_factory.new_client(), name.clone(), query_class, query_type)
                .and_then(move |message| { 
                    (*success_state.borrow_mut()).1 = message; 
                    Ok(Loop::Break(success_state)) 
                })
                .or_else(move |error| { 
                    let next_step = |state: Rc<RefCell<(i32, Option<_>)>>| {
                        (*state.borrow_mut()).0 -= 1;
                        if (*state.borrow()).0 > 0 { Ok(Loop::Continue(state)) }
                        else                       { Ok(Loop::Break(state))    } 
                    };
                    match *error.kind() {
                        ClientErrorKind::Timeout => {
                            next_step(state)
                        },
                        ClientErrorKind::Canceled(e) => {
                            if (*state.borrow()).0 == 0 {error!("{}", e)}
                            next_step(state)
                        },
                        _  => {
                            let err = ResolverError::DnsClientError(error);
                            error!("{}", err);
                            Err(err)
                        }
                    }
                    
                })
        }).map(move |state| {
            let state = Rc::try_unwrap(state).unwrap().into_inner();
            match state.1 {
                Some(..) => (),
                None     => warn!("Failed to resolve {:?}: Connection Timeout", name_copy.to_string()),
            }
            state.1
        });

        Box::new(retry_loop)
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

use trust_dns::rr::RData::{A, AAAA, PTR};

impl<'a> From<&'a Record> for DnsData {
    fn from(record: &'a Record) -> DnsData {
        let name = if let &PTR(ref name) = record.rdata() {Some(name.to_string())} else {None};
        let ipv4 = if let &A(ip)         = record.rdata() {Some(ip.to_string())}   else  {None};
        let ipv6 = if let &AAAA(ip)      = record.rdata() {Some(ip.to_string())}   else  {None};
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

fn report_status<T>(data: Option<T>, done_tx: mpsc::Sender<ResolveStatus>) -> Option<T> {
    if data.is_some() {
        done_tx.send(ResolveStatus::Success).wait().unwrap();
    } else {
        done_tx.send(ResolveStatus::Failure).wait().unwrap();
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

impl NS {
    pub fn to_string(&self) -> String {
        match *self {
            NS::Known(ref addr) => addr.to_string(),
            NS::Unknown(ref dom) => dom.clone()
        }
    }
}

struct State {
    handle: Handle,
    client_factory: Rc<ClientFactory>,
    ns: Vec<NS>,
    result: Vec<DnsData>
}

#[derive(Copy, Clone)]
pub enum ResolveStatus {
    Success,
    Failure
}

