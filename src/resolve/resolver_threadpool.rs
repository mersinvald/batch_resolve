use std::sync::mpsc;
use batch::QueryType;
use resolve::resolver::TrustDNSResolver;
use resolve::batch::ResolveStatus;

use futures::Future;
use resolve::error::ResolverError;
use resolve::dns::DnsStore;
use resolve::dns::CountingDns;
use futures::Stream;
use futures::stream;
use futures;

use std::thread;
use std::net::SocketAddr;
use tokio_core::reactor::Core;

lazy_static! {
    static ref GOOGLE_DNS: SocketAddr = "8.8.8.8:53".parse().unwrap();
}

pub struct ResolverThreadPool {
    workers: Vec<mpsc::Sender<ResolveTask>>,
    last: usize,
}

impl ResolverThreadPool {
    pub fn new(num_cpus: usize, status: mpsc::Sender<ResolveStatus>) -> Self {
        let workers = (0..num_cpus).map(|_| {
            let (tx, rx) = mpsc::channel();
            ResolverThread::spawn(rx, status.clone());
            tx
        }).collect();

        ResolverThreadPool {
            workers: workers,
            last: 0,
        }
    }

    pub fn num_cpus() -> Self {
        unimplemented!()
    }

    pub fn spawn(&mut self, task: ResolveTask) {
        self.workers[self.last].send(task).unwrap();
        self.last = (self.last + 1) % self.workers.len();
    }

    pub fn start(self) {
        // workers are dropped now, so channels are closed and 
        // threads proceed to core.run()
    }
}

struct ResolverThread;

impl ResolverThread {
    pub fn spawn(tasks: mpsc::Receiver<ResolveTask>, 
                 status: mpsc::Sender<ResolveStatus>) {
        thread::spawn(|| Self::thread_fn(tasks, status));
    }

    fn thread_fn(tasks: mpsc::Receiver<ResolveTask>, 
                 status: mpsc::Sender<ResolveStatus>) {
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let (sa_tx, sa_rx) = futures::sync::mpsc::channel(1000);
        let resolver = TrustDNSResolver::new(handle.clone(), sa_tx);

        let mut futures = vec![];
        for task in &tasks {
            futures.push(task.resolve(&resolver)
                             .map_err(|_| ()));
        }

        let future = stream::iter(futures.into_iter().map(|f| Ok(f)))
            .buffer_unordered(1000)
            .collect();

        handle.spawn(future.map(|_|()));

        let status_future = sa_rx.for_each(|s| {
            status.send(s).unwrap();
            Ok(())
        });

        core.run(status_future).unwrap();
    }
}

pub struct ResolveTask {
    pub tx: mpsc::Sender<Vec<String>>,
    pub name: String,
    pub qtype: QueryType,
}

impl ResolveTask {
    pub fn resolve(&self, resolver: &TrustDNSResolver) 
        -> Box<Future<Item=(), Error=ResolverError>>
        //where F: 
    {
        let tx = self.tx.clone();

        let future = resolver.resolve(*GOOGLE_DNS, &self.name, self.qtype)
            .and_then(move |result| Ok(tx.send(result).unwrap()));

        Box::new(future)
    }
}