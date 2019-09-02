use std::borrow::Borrow;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::str;

use futures::future;
use futures::future::Loop;
use futures::Future;
use tokio_core::reactor::Handle;

use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::error::ClientError;
use trust_dns::error::ClientErrorKind;
use trust_dns::op::message::Message;
use trust_dns::rr::dns_class::DNSClass;
use trust_dns::rr::domain::Name;
use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::resource::Record;
use trust_dns::udp::UdpClientStream;

use config::CONFIG;
use resolve::batch::{QueryType, ResolveStatus, StatusTx};
use resolve::error::*;

fn make_client(loop_handle: Handle, name_server: SocketAddr) -> BasicClientHandle {
    let (stream, stream_handle) = UdpClientStream::new(name_server, loop_handle.clone());

    ClientFuture::new(stream, stream_handle, loop_handle, None)
}

#[derive(Clone)]
struct ClientFactory {
    loop_handle: Handle,
    name_server: SocketAddr,
}

impl ClientFactory {
    pub fn new(loop_handle: Handle, name_server: SocketAddr) -> ClientFactory {
        ClientFactory {
            loop_handle: loop_handle,
            name_server: name_server,
        }
    }

    fn new_client(&self) -> BasicClientHandle {
        make_client(self.loop_handle.clone(), self.name_server)
    }

    fn dns(&self) -> SocketAddr {
        self.name_server
    }
}

pub struct TrustDNSResolver {
    loop_handle: Handle,
    status_tx: StatusTx,
    timeout_retries: u32,
}

impl TrustDNSResolver {
    pub fn new(loop_handle: Handle, status_tx: StatusTx) -> Self {
        TrustDNSResolver {
            loop_handle: loop_handle.clone(),
            status_tx: status_tx,
            timeout_retries: CONFIG.read().unwrap().timeout_retries(),
        }
    }
}

impl TrustDNSResolver {
    pub fn resolve(
        &self,
        dns: SocketAddr,
        name: &str,
        query_type: QueryType,
    ) -> Box<Future<Item = Vec<String>, Error = ResolverError>> {
        let client_factory = ClientFactory::new(self.loop_handle.clone(), dns);

        self.status_tx.send(ResolveStatus::Started).unwrap();
        let status_tx = self.status_tx.clone();

        let future = match query_type {
            QueryType::PTR => self.reverse_resolve(client_factory, name),
            _ => self.simple_resolve(client_factory, name, query_type.into()),
        };

        let name = name.to_owned();
        let future = future
            .map(move |msg| msg.extract_answer(query_type))
            .then(move |rv| rv.report_status(&name, status_tx))
            .then(move |rv| rv.partial_ok());

        Box::new(future)
    }

    // Simple DNS lookup queries
    fn simple_resolve(
        &self,
        client_factory: ClientFactory,
        name: &str,
        rtype: RecordType,
    ) -> Box<Future<Item = Message, Error = ResolverError>> {
        Box::new(Self::resolve_retry(
            client_factory,
            self.timeout_retries,
            Name::parse(name, Some(&Name::root())).unwrap(),
            DNSClass::IN,
            rtype,
        ))
    }

    // Reverse DNS queries
    fn reverse_resolve(
        &self,
        client_factory: ClientFactory,
        ip: &str,
    ) -> Box<Future<Item = Message, Error = ResolverError>> {
        let mut labels = ip.split('.').map(str::to_owned).collect::<Vec<_>>();
        labels.reverse();

        let name = Name::with_labels(labels).label("in-addr").label("arpa");

        Box::new(self.recurse_ptr(client_factory, name, DNSClass::IN, RecordType::PTR))
    }

    // Recursive DNS request for PTR queries
    fn recurse_ptr(
        &self,
        client_factory: ClientFactory,
        name: Name,
        query_class: DNSClass,
        record_type: RecordType,
    ) -> Box<Future<Item = Message, Error = ResolverError>> {
        // Because recursion is not possible with futures this implementation of Depth-First lookup
        // uses state with discovered nameservers excluding visited ones to avoid infinite loops
        struct State {
            handle: Handle,
            client_factory: ClientFactory,
            nameservers: Vec<NS>,
            visited: HashSet<NS>,
            answer: Option<Message>,
        }

        impl State {
            pub fn pop_ns(&mut self) -> Option<NS> {
                self.nameservers.pop().map(|ns| {
                    self.visited.insert(ns.clone());
                    ns
                })
            }

            pub fn push_nameservers<I, B>(&mut self, iter: I)
            where
                I: IntoIterator<Item = B>,
                B: Borrow<Name>,
            {
                let new_nameservers = iter
                    .into_iter()
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

        let timeout_retries = self.timeout_retries;
        let state = State {
            handle: self.loop_handle.clone(),
            client_factory: client_factory.clone(),
            nameservers: vec![NS::Known(client_factory.dns())],
            visited: HashSet::new(),
            answer: None,
        };

        let resolve_loop = future::loop_fn(state, move |mut state| {
            Self::resolve_with_ns(
                state.handle.clone(),
                state.client_factory.clone(),
                timeout_retries,
                state.pop_ns().unwrap(),
                name.clone(),
                query_class,
                record_type,
            )
            .map(move |message| {
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

    // Perform DNS query with some nameserver.
    // If nameserver is not a SocketAddr, resolve the domain first.
    fn resolve_with_ns(
        loop_handle: Handle,
        client_factory: ClientFactory,
        timeout_retries: u32,
        nameserver: NS,
        name: Name,
        query_class: DNSClass,
        record_type: RecordType,
    ) -> Box<Future<Item = Message, Error = ResolverError>> {
        debug!(
            "Resolving {:?} with nameserver {:?}",
            name.to_string(),
            nameserver.to_string()
        );
        let ns_resolve: Box<Future<Item = Option<SocketAddr>, Error = ResolverError>> =
            match nameserver {
                NS::Known(addr) => future::ok(Some(addr)).boxed(),
                NS::Unknown(domain) => Box::new(
                    Self::resolve_retry(
                        client_factory.clone(),
                        timeout_retries,
                        Name::parse(&domain, Some(&Name::root())).unwrap(),
                        DNSClass::IN,
                        RecordType::A,
                    )
                    .map(|msg| {
                        msg.extract_answer(QueryType::A)
                            .into_iter()
                            .nth(0)
                            .map(|mut ip| {
                                ip.push_str(":53");
                                ip
                            })
                            .and_then(|ip| {
                                ip.parse::<SocketAddr>()
                                    .map_err(|e| {
                                        error!("Invalid IP({:?}): {:?}", ip, e);
                                        e
                                    })
                                    .ok()
                            })
                    }),
                ),
            };

        let future = ns_resolve.then(move |result| match result {
            Ok(Some(nameserver)) => Self::resolve_retry(
                ClientFactory::new(loop_handle, nameserver),
                timeout_retries,
                name.clone(),
                query_class,
                record_type,
            ),
            Ok(None) => future::err(ResolverError::NameServerNotResolved).boxed(),
            Err(err) => future::err(err).boxed(),
        });

        Box::new(future)
    }

    // Retry-on-timeout enabled resolve
    fn resolve_retry(
        client_factory: ClientFactory,
        timeout_retries: u32,
        name: Name,
        query_class: DNSClass,
        record_type: RecordType,
    ) -> Box<Future<Item = Message, Error = ResolverError>> {
        struct State {
            tries_left: u32,
            message: Option<Message>,
        };

        impl State {
            fn new(tries: u32) -> Self {
                State {
                    tries_left: tries,
                    message: None,
                }
            }

            fn next_step(mut self) -> Result<Loop<Self, Self>, ResolverError> {
                self.tries_left -= 1;
                if self.tries_left > 0 {
                    Ok(Loop::Continue(self))
                } else {
                    Ok(Loop::Break(self))
                }
            }

            fn has_next_step(&self) -> bool {
                self.tries_left > 0
            }

            fn with_message(mut self, message: Message) -> State {
                self.message = Some(message);
                self
            }

            fn into_message(self) -> Option<Message> {
                self.message
            }
        }

        let state = State::new(timeout_retries);

        let retry_loop = {
            future::loop_fn(state, move |state| {
                Self::_resolve(
                    client_factory.new_client(),
                    name.clone(),
                    query_class,
                    record_type,
                )
                .then(move |result| match result {
                    Ok(message) => {
                        trace!("Received DNS message: {:?}", message.answers());
                        Ok(Loop::Break(state.with_message(message)))
                    }
                    Err(err) => match *err.kind() {
                        ClientErrorKind::Timeout => state.next_step(),
                        ClientErrorKind::Canceled(e) => {
                            if !state.has_next_step() {
                                error!("{}", e)
                            }
                            state.next_step()
                        }
                        _ => Err(ResolverError::DnsClientError(err)),
                    },
                })
            })
        };

        let future = retry_loop.then(move |result| match result {
            Ok(state) => {
                let message = state.into_message();
                match message {
                    Some(message) => Ok(message),
                    None => Err(ResolverError::ConnectionTimeout),
                }
            }
            Err(err) => Err(err),
        });

        Box::new(future)
    }

    fn _resolve(
        mut client: BasicClientHandle,
        name: Name,
        query_class: DNSClass,
        record_type: RecordType,
    ) -> Box<Future<Item = Message, Error = ClientError>> {
        Box::new(client.query(name, query_class, record_type))
    }
}

use trust_dns::rr::RData;

trait FromRecord<B>
where
    B: Borrow<Record>,
    Self: Sized,
{
    fn from(r: B, qtype: QueryType) -> Option<Self>;
}

impl<B> FromRecord<B> for String
where
    B: Borrow<Record>,
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

        variants_to_string!(A, AAAA, NS, PTR)
    }
}

trait ExtractAnswer {
    fn extract_answer(&self, qtype: QueryType) -> Vec<String>;
}

impl ExtractAnswer for Message {
    fn extract_answer(&self, qtype: QueryType) -> Vec<String> {
        self.answers()
            .into_iter()
            .map(|record| <String as FromRecord<_>>::from(record, qtype))
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect()
    }
}

trait ReportStatus {
    fn report_status(self, name: &str, status_tx: StatusTx) -> Self;
}

impl<T> ReportStatus for Result<Vec<T>, ResolverError> {
    fn report_status(self, name: &str, status_tx: StatusTx) -> Self {
        match self.as_ref() {
            Ok(vec) => {
                if vec.is_empty() {
                    status_tx.send(ResolveStatus::Failure).unwrap();
                } else {
                    status_tx.send(ResolveStatus::Success).unwrap();
                }
            }
            Err(error) => match *error {
                ResolverError::ConnectionTimeout | ResolverError::NameServerNotResolved => {
                    debug!("failed to resolve {:?}: {}", name, error);
                    status_tx.send(ResolveStatus::Failure).unwrap();
                }
                _ => {
                    error!("failed to resolve {:?}: {}", name, error);
                    status_tx.send(ResolveStatus::Error).unwrap();
                }
            },
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
            Err(ResolverError::ConnectionTimeout)
            | Err(ResolverError::NameServerNotResolved)
            | Err(ResolverError::NotFound) => Ok(vec![]),
            Ok(vec) => Ok(vec),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
enum NS {
    Known(SocketAddr),
    Unknown(String),
}

impl NS {
    pub fn to_string(&self) -> String {
        match *self {
            NS::Known(ref addr) => addr.to_string(),
            NS::Unknown(ref dom) => dom.clone(),
        }
    }

    pub fn try_from<B>(name: B) -> Result<NS, ()>
    where
        B: Borrow<Name>,
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
