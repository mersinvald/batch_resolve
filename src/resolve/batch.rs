// TODO check out patches in TrustDNS to store domains and ips as dictinct types.
use std::rc::Rc;
use std::cell::RefCell;

use tokio_core::reactor::Core;

use futures::sync::mpsc;
use futures::Stream;
use futures::stream;
use futures::Future;
use futures::future;

use resolve::resolver::*;
use resolve::error::ResolverError;
use config::CONFIG;

#[derive(Debug, Default, Copy, Clone)]
pub struct Status {
    pub done: u64,
    pub success: u64,
    pub fail: u64,
    pub errored: u64,
}

#[derive(Copy, Clone)]
pub enum ResolveStatus {
    Success,
    Failure,
    Error
}

pub type OutVec = Rc<RefCell<Vec<String>>>;

pub struct Batch<I> 
    where I: IntoIterator<Item=String> + 'static
{
    event_loop:  Core,
    tasks:       Vec<BatchTask<I>>,
    outputs:     Vec<OutVec>,
    done_tx:     mpsc::Sender<ResolveStatus>,
    done_rx:     mpsc::Receiver<ResolveStatus>,
    status_fn:   Box<Fn(Status)>
}

impl<I> Batch<I> 
    where I: IntoIterator<Item=String> + 'static,
{
    pub fn new() -> Self {
        let event_loop = Core::new().unwrap();
        let (done_tx, done_rx) = mpsc::channel(1024);
        Batch {
            event_loop: event_loop,
            tasks: vec![],
            outputs: vec![],
            done_tx: done_tx,
            done_rx: done_rx,
            status_fn: Box::new(|_| ()),
        }
    }

    pub fn register_status_callback(&mut self, func: Box<Fn(Status)>) {
        self.status_fn = func
    }

    pub fn add_task(&mut self, input: I, output: OutVec, qtype: QueryType) {
        self.tasks.push(BatchTask::new(
            input,
            TrustDNSResolver::new(CONFIG.dns_servers(), self.event_loop.handle(), self.done_tx.clone()),
            qtype
        ));
        self.outputs.push(output)
    }

    pub fn run(mut self) {
        let tasks_cnt = self.tasks.len();

        let mut futures = vec![];

        for _ in 0..tasks_cnt {
            let task = self.tasks.pop().unwrap();
            let out  = self.outputs.pop().unwrap();

            futures.push(task.resolve().and_then(move |result| {
                (*out.borrow_mut()).extend(result);
                Ok(())
            }));
        }

        let all_future = future::join_all(futures);

        // Run status task 
        let handle = self.event_loop.handle();
        let mut status = Status::default();
        let status_fn = self.status_fn;

        handle.spawn(self.done_rx.for_each(move |resolve_status| {
            status.done += 1;
            match resolve_status {
                ResolveStatus::Success => status.success += 1,
                ResolveStatus::Failure => status.fail += 1,
                ResolveStatus::Error   => status.errored += 1,
            }
            status_fn(status);
            Ok(())
        }));
        

        self.event_loop.run(all_future).unwrap();
    }
}

arg_enum!{
    #[derive(Copy, Clone, Debug)]
    pub enum QueryType {
        A,
        AAAA,
        PTR,
        NS
    }
}

use trust_dns::rr::RecordType;
impl Into<RecordType> for QueryType {
    fn into(self) -> RecordType {
        match self {
            QueryType::A    => RecordType::A,
            QueryType::AAAA => RecordType::AAAA,
            QueryType::PTR  => RecordType::PTR,
            QueryType::NS   => RecordType::NS
        }
    } 
}

pub struct BatchTask<I> 
    where I: IntoIterator<Item=String>
{
    input:    I,
    qtype:    QueryType,
    resolver: TrustDNSResolver,
}

impl<I> BatchTask<I> 
    where I: IntoIterator<Item=String> + 'static,
{
    fn new(input: I, resolver: TrustDNSResolver, qtype: QueryType) -> Self {
        BatchTask {
            input: input,
            resolver: resolver,
            qtype: qtype
        }
    }

    fn resolve(self) -> Box<Future<Item=Vec<String>, Error=ResolverError>> {
        let stream = Self::resolve_stream(self.input, self.qtype, self.resolver);

        // Flatten results
        let future = stream.collect()
            .map(|x| x.into_iter()
                      .flat_map(|x| x.into_iter())
                      .collect());

        Box::new(future)
    }

    fn resolve_stream(input: I, qtype: QueryType, resolver: TrustDNSResolver) -> Box<Stream<Item=Vec<String>, Error=ResolverError>> 
        where I: IntoIterator<Item=String>
    {
        let stream = stream::iter::<_, _, ResolverError>(input.into_iter().map(|x| Ok(x)))
            .map(move |name| resolver.resolve(&name, qtype))
            .buffer_unordered(CONFIG.task_buffer_size());

        Box::new(stream)
    }
}