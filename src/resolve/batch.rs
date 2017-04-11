// TODO check out patches in TrustDNS to store domains and ips as dictinct types.
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use tokio_core::reactor::Core;

use std::thread;
use std::sync::mpsc;
use futures::Stream;
use futures::stream;
use futures::Future;
use futures::future;

use resolve::dns::dns_stream;
use resolve::resolver::*;
use resolve::error::ResolverError;
use resolve::resolver_threadpool::ResolverThreadPool;
use resolve::resolver_threadpool::ResolveTask;
use config::CONFIG;

#[derive(Debug, Default, Copy, Clone)]
pub struct Status {
    pub done: u64,
    pub success: u64,
    pub fail: u64,
    pub errored: u64,
    pub running: u64,
}

#[derive(Copy, Clone, Debug)]
pub enum ResolveStatus {
    Started,
    Success,
    Failure,
    Error
}

pub type OutVec = Arc<Mutex<Vec<String>>>;

pub struct Batch<I> 
    where I: IntoIterator<Item=String> + 'static
{
    event_loop:  Core,
    tasks:       Vec<BatchTask<I>>,
    outputs:     Vec<OutVec>,
    status_fn:   Box<Fn(Status)>
}

impl<I> Batch<I> 
    where I: IntoIterator<Item=String> + 'static,
{
    pub fn new() -> Self {
        let event_loop = Core::new().unwrap();
        Batch {
            event_loop: event_loop,
            tasks: vec![],
            outputs: vec![],
            status_fn: Box::new(|_| ()),
        }
    }

    pub fn register_status_callback(&mut self, func: Box<Fn(Status)>) {
        self.status_fn = func
    }

    pub fn add_task(&mut self, input: I, output: OutVec, qtype: QueryType) {
        self.tasks.push(BatchTask::new(
            input,
            qtype
        ));
        self.outputs.push(output)
    }

    pub fn run(mut self) {
        let tasks_cnt = self.tasks.len();

        let (status_tx, status_rx) = mpsc::channel();

        let mut resolve_pool = ResolverThreadPool::new(4, status_tx);
        
        // Run status task 
        for _ in 0..tasks_cnt {
            let task = self.tasks.pop().unwrap();
            let out  = self.outputs.pop().unwrap();
            let (r_tx, r_rx) = mpsc::channel();
            for name in task.input {
                trace!("Spawning task {} {}", name, task.qtype);
                resolve_pool.spawn(ResolveTask {
                    tx: r_tx.clone(),
                    name: name,
                    qtype: task.qtype,
                });
            }

            thread::spawn(move || {
                for result in r_rx {
                    out.lock().unwrap().extend(result)
                }
            });
        }

        trace!("Starting resolve job on thread pool");
        resolve_pool.start();

        let status_fn = self.status_fn;
        let mut status = Status::default();
        
        for resolve_status in status_rx {
            trace!("Resolve status: received {:?}", resolve_status);
            match resolve_status {
                ResolveStatus::Started => status.running += 1,
                other => {
                    status.done += 1;
                    status.running -= 1;
                    match other {
                        ResolveStatus::Success => status.success += 1,
                        ResolveStatus::Failure => status.fail += 1,
                        ResolveStatus::Error   => status.errored += 1,
                        _ => ()
                    }
                }
            }
            status_fn(status);
        }
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
}

impl<I> BatchTask<I> 
    where I: IntoIterator<Item=String> + 'static,
{
    fn new(input: I, qtype: QueryType) -> Self {
        BatchTask {
            input: input,
            qtype: qtype
        }
    }

   /* fn resolve(self) -> Box<Future<Item=Vec<String>, Error=ResolverError>> {
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
        //let futures = input.into_iterator()
        let dns_store = CONFIG.dns_store();
        let task_buffer_size = dns_store.overall_qps() + dns_store.average_qps();

        debug!("Task buffer size: {}", task_buffer_size);

        let future = dns_stream(dns_store)
            .zip(stream::iter(input.into_iter().map(|x| Ok(x))))
            .map(move |(dns, name)| resolver.resolve(dns, &name, qtype))
            .buffer_unordered(task_buffer_size);

        Box::new(future)
    }
    */
}