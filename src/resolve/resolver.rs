use std::str;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::borrow::Borrow;

use futures::Future;
use futures::Sink;
use futures::future;
use futures::future::Loop;
use futures::sync::mpsc;
use tokio_core::reactor::Handle;

use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::udp::UdpClientStream;
use trust_dns::error::ClientError;
use trust_dns::rr::domain::Name;
use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::dns_class::DNSClass;
use trust_dns::rr::resource::Record;
use trust_dns::op::message::Message;
use trust_dns::error::ClientErrorKind;

use resolve::error::*;
use resolve::batch::{ResolveStatus, QueryType};
use config::CONFIG;

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
    dns_server_addrs: Rc<Vec<SocketAddr>>,
    last_chosen: RefCell<usize>,
    loop_handle: Handle,
}

impl LevellingClientFactory {
    pub fn new<I>(dns_server_addrs: I, loop_handle: Handle) -> LevellingClientFactory 
        where I: Into<Rc<Vec<SocketAddr>>>
    {
        LevellingClientFactory {
            dns_server_addrs: dns_server_addrs.into(),
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
    pub fn new<I>(dns_server_addrs: I, loop_handle: Handle, done_tx: mpsc::Sender<ResolveStatus>) -> Self 
        where I: Into<Rc<Vec<SocketAddr>>>
    {
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
    pub fn resolve(&self, name: &str, query_type: QueryType) -> Box<Future<Item=Vec<String>, Error=ResolverError>> {
        let done_tx = self.done_tx.clone();
        
        let future = match query_type {
            QueryType::PTR => self.reverse_resolve(name),
            _              => self.simple_resolve(name, query_type.into()),
        };

        let name = name.to_owned();
        let future = future.map(move |msg| msg.extract_answer(query_type))
            .then(move |rv| rv.report_status(&name, done_tx))
            .then(move |rv| rv.partial_ok());

        Box::new(future)
    }

    fn simple_resolve(&self, name: &str, rtype: RecordType) -> Box<Future<Item=Message, Error=ResolverError>> {
        Box::new(
            Self::resolve_retry(
                self.client_factory.clone(),
                Name::parse(&name, Some(&Name::root())).unwrap(), 
                DNSClass::IN, 
                rtype, 
        ))
    }

    fn reverse_resolve(&self, ip: &str) -> Box<Future<Item=Message, Error=ResolverError>> {
        let mut labels = ip.split('.').map(str::to_owned).collect::<Vec<_>>();
        labels.reverse();

        let name = Name::with_labels(labels).label("in-addr").label("arpa");
    
        Box::new(
            self.recurse_ptr(
                name,
                DNSClass::IN, 
                RecordType::PTR,
        ))
    }

    fn recurse_ptr(&self, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Message, Error=ResolverError>>
    {
        struct State {
            handle: Handle,
            client_factory: Rc<ClientFactory>,
            nameservers: Vec<NS>,
            visited: HashSet<NS>,
            answer: Option<Message>
        }

        impl State {
            pub fn pop_ns(&mut self) -> Option<NS> {
                self.nameservers.pop().map(|ns| {
                    self.visited.insert(ns.clone());
                    ns    
                })
            }

            pub fn push_nameservers<I, B>(&mut self, iter: I) 
                where I: IntoIterator<Item=B>,
                    B: Borrow<Name>
            {
                let new_nameservers = iter.into_iter()
                    .map(NS::try_from)
                    .filter_map(Result::ok)
                    .filter(|ns| !self.visited.contains(ns))
                    .collect::<Vec<_>>();
                self.nameservers.extend(new_nameservers)
            }

            pub fn add_answer(&mut self, answer: Message) {
                self.answer = Some(answer)
            }
        }

        let state = State {
            handle: self.loop_handle.clone(),
            client_factory: self.client_factory.clone(),
            nameservers: vec![NS::Known(self.client_factory.next_namesrv())],
            visited: HashSet::new(),
            answer: None,
        };

        let resolve_loop = future::loop_fn(state, move |mut state| {
            Self::resolve_with_ns(
                state.handle.clone(),
                state.client_factory.clone(),
                state.pop_ns().unwrap(),
                name.clone(), query_class, query_type
            ).map(move |message| {
                state.push_nameservers(message.name_servers().iter().map(Record::name));
                state.add_answer(message);
                state
            })
            .and_then(|state| {
                if !state.answer.is_none() || state.nameservers.is_empty() {
                    Ok(Loop::Break(state))
                } else {
                    Ok(Loop::Continue(state))
                }
            })
        });

        Box::new(resolve_loop.and_then(|state| {
            if let Some(answer) = state.answer {
                Ok(answer)
            } else {
                Err(ResolverError::NotFound)
            }
        }))
    }

    fn resolve_with_ns(loop_handle: Handle, client_factory: Rc<ClientFactory>, nameserver: NS, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Message, Error=ResolverError>>
    {
        debug!("Resolving {:?} with nameserver {:?}", name.to_string(), nameserver.to_string());
        let ns_resolve: Box<Future<Item=Option<SocketAddr>, Error=ResolverError>> = match nameserver {
            NS::Known(addr) => future::ok(Some(addr)).boxed(),
            NS::Unknown(domain) => {
                Box::new(Self::resolve_retry(
                    client_factory.clone(),
                    Name::parse(&domain, Some(&Name::root())).unwrap(), 
                    DNSClass::IN, 
                    RecordType::A,
                ).map(|msg| msg.extract_answer(QueryType::A)
                    .into_iter().nth(0)
                    .map(|mut ip| { ip.push_str(":53"); ip } )
                        .and_then(|ip| ip.parse::<SocketAddr>()
                            .map_err(|e| {
                                error!("Invalid IP({:?}): {:?}", ip, e);
                                e
                            })
                            .ok()
                )))
            }
        };

        
        let future = ns_resolve.then(move |result| {
            match result {
                Ok(Some(nameserver)) => Self::resolve_retry(
                                        Rc::new(FixedClientFactory::new(loop_handle, nameserver)),
                                        name.clone(),
                                        query_class, 
                                        query_type),
                Ok(None) => future::err(ResolverError::NameServerNotResolved).boxed(),
                Err(err) => future::err(err).boxed(),

            }
        });

        Box::new(future)
    }

    fn resolve_retry(client_factory: Rc<ClientFactory>, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Message, Error=ResolverError>>
    {
        struct State(RefCell<u32>, RefCell<Option<Message>>);
        impl State {
            fn new() -> Self {
                State(RefCell::new(CONFIG.timeout_retries()), RefCell::new(None))
            }

            fn next_step(state: Rc<Self>) -> Result<Loop<Rc<Self>, Rc<Self>>, ResolverError> {
                *state.0.borrow_mut() -= 1;
                if *state.0.borrow() > 0 { 
                    Ok(Loop::Continue(state)) 
                } else { 
                    Ok(Loop::Break(state))    
                } 
            }

            fn has_next_step(state: &Rc<Self>) -> bool {
                *state.0.borrow() > 0
            }

            fn set_message(state: &Rc<Self>, message: Option<Message>) {
                *state.1.borrow_mut() = message
            }

            fn get_message(state: &Rc<Self>) -> Option<Message> {
                state.1.borrow().clone()
            }
        }

        let state = Rc::new(State::new());

        let retry_loop = {
            let name = name.clone();

            future::loop_fn(state, move |state| {
                let and_state = state.clone();
                let or_state = state.clone();
                Self::_resolve(client_factory.new_client(), name.clone(), query_class, query_type)
                    .then(move |result| match result {
                        Ok(message) => {
                            trace!("Received DNS message: {:?}", message.answers()); 
                            State::set_message(&state, Some(message)); 
                            Ok(Loop::Break(and_state)) 
                        },
                        Err(err) => match *err.kind() {
                            ClientErrorKind::Timeout => {
                                State::next_step(or_state)
                            },
                            ClientErrorKind::Canceled(e) => {
                                if !State::has_next_step(&or_state) {error!("{}", e)}
                                State::next_step(or_state)
                            },
                            _  => Err(ResolverError::DnsClientError(err))
                        },
                    }
                )
            })
        };
        
        let future = retry_loop.then(move |result| {
            match result {
                Ok(state) => {
                    let message = State::get_message(&state);
                    match message {
                        Some(message) => Ok(message),
                        None     => Err(ResolverError::ConnectionTimeout),
                    }
                },
                Err(err) => Err(err)
            }
        });

        Box::new(future)
    }

    fn _resolve(mut client: BasicClientHandle, name: Name, query_class: DNSClass, query_type: RecordType) 
        -> Box<Future<Item=Message, Error=ClientError>>
    {
        Box::new(
            client.query(
                name,
                query_class,
                query_type
            )
        )
    }
}

use trust_dns::rr::RData;

trait FromRecord<B>
    where B: Borrow<Record>,
          Self: Sized
{
    fn from(r: B, qtype: QueryType) -> Option<Self>;
}

impl<B> FromRecord<B> for String 
    where B: Borrow<Record>
{
    fn from(r: B, qtype: QueryType) -> Option<Self> {
        let r = r.borrow();

        macro_rules! variants_to_string {
            ($($x:tt),*) => {
                match (qtype, r.rdata()) {
                    $(
                        (QueryType::$x, &RData::$x(ref data)) => Some(data.to_string()),
                    )*
                    _ => None
                }
            }
        }
    
        variants_to_string!(
            A, 
            AAAA,
            NS,
            PTR
        )  
    }
}

trait ExtractAnswer {
    fn extract_answer(&self, qtype: QueryType) -> Vec<String>;
}

impl ExtractAnswer for Message {
    fn extract_answer(&self, qtype: QueryType) -> Vec<String> {
        self.answers().into_iter() 
            .map(|record| <String as FromRecord<_>>::from(record, qtype))
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect()
    }
}

trait ReportStatus {
    fn report_status(self, name: &str, done_tx: mpsc::Sender<ResolveStatus>) -> Self;    
}

impl<T> ReportStatus for Result<Vec<T>, ResolverError> {
    fn report_status(self, name: &str, done_tx: mpsc::Sender<ResolveStatus>) -> Self {
        match self.as_ref() {
            Ok(vec) => if vec.is_empty() {
                done_tx.send(ResolveStatus::Failure).wait().unwrap();
            } else {
                done_tx.send(ResolveStatus::Success).wait().unwrap();
            },
            Err(error) => {
                match *error {
                    ResolverError::ConnectionTimeout |
                    ResolverError::NameServerNotResolved => {
                        debug!("failed to resolve {:?}: {}", name, error);
                        done_tx.send(ResolveStatus::Failure).wait().unwrap();
                    }
                    _ => {
                        error!("failed to resolve {:?}: {}", name, error);
                        done_tx.send(ResolveStatus::Error).wait().unwrap();
                    }
                }
            }
        }
        self
    }    
}

trait PartialOk<T> {
    fn partial_ok(self) -> Result<Vec<T>, ResolverError>;
}

impl<T> PartialOk<T> for Result<Vec<T>, ResolverError> {
    fn partial_ok(self) -> Result<Vec<T>, ResolverError> {
        match self {
            Err(ResolverError::ConnectionTimeout) |
            Err(ResolverError::NameServerNotResolved) |
            Err(ResolverError::NotFound) 
                     => Ok(vec![]),
            Ok(vec)  => Ok(vec),
            Err(err) => Err(err)
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
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

    pub fn try_from<B>(name: B) -> Result<NS, ()> 
        where B: Borrow<Name>
    {
        let name = name.borrow(); 
        if name.num_labels() != 0 {
            Ok(NS::Unknown(name.to_string()))
        } else {
            Err(())
        }
    }
}

impl From<SocketAddr> for NS {
    fn from(addr: SocketAddr) -> NS {
        NS::Known(addr)
    }
}