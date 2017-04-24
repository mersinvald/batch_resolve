use std::sync::mpsc;
use std::thread;
use std::net::SocketAddr;

use tokio_core::reactor::Core;
use futures;
use futures::Stream;
use futures::stream;
use futures::Future;

use crossbeam;
use num_cpus;

use batch::QueryType;
use resolve::resolver::TrustDNSResolver;
use resolve::batch::ResolveStatus;
use resolve::error::ResolverError;
use config::CONFIG;

pub struct ResolverThreadPool {
    tasks: Vec<ResolveTask>,
    workers_cnt: usize
}

impl ResolverThreadPool {
    pub fn new(num_cpus: usize) -> Self {
        ResolverThreadPool {
            tasks: vec![],
            workers_cnt: num_cpus
        }
    }

    pub fn num_cpus() -> Self {
        Self::new(num_cpus::get())
    }

    pub fn spawn(&mut self, task: ResolveTask) {
        self.tasks.push(task)
    }

    pub fn start(self, status: mpsc::Sender<ResolveStatus>) {
        let tasks_cnt = self.tasks.len();
        let chunk_size = tasks_cnt / self.workers_cnt;
        let sim_tasks = CONFIG.read().unwrap().tasks() as usize / self.workers_cnt ;

        crossbeam::scope(|scope| {
            scope.defer(|| debug!("Exiting crosspbeam scope"));
            for chunk in self.tasks.chunks(chunk_size) 
                .map(|chunk| chunk.to_vec()) 
            {
                let status = status.clone();
                let dns = CONFIG.read().unwrap()
                    .dns_list()
                    .to_vec();

                scope.spawn(move || {
                    let thread = thread::current(); 
                    let tname = thread.name()
                        .unwrap_or("Unknown");

                    debug!("Started worker thread ({})", tname);
                    ResolverThread::thread_fn(chunk, status, dns, sim_tasks);
                    debug!("Terminated worker thread: ({})", tname);
                });
            }
        })
    }
}

struct ResolverThread;

impl ResolverThread {
    fn thread_fn(tasks: Vec<ResolveTask>, 
                 status: mpsc::Sender<ResolveStatus>, 
                 dns: Vec<SocketAddr>,
                 sim_tasks: usize) 
    {
        debug!("Simultaneous tasks: {}", sim_tasks);
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let (sa_tx, sa_rx) = futures::sync::mpsc::channel(1000);

        {  
            let resolver = TrustDNSResolver::new(handle.clone(), sa_tx);

            let futures_stream =  {
                let fs = tasks.into_iter()
                    .enumerate()
                    .map(move |(idx, task)| {
                        let idx = idx % dns.len();
                        let dns = dns[idx];
                        task.resolve(&resolver, dns)
                    });
                stream::iter::<_, _, _>(fs.map(|x| Ok(x)))
            };

            let future = futures_stream
                .buffer_unordered(sim_tasks)
                .collect();

            handle.spawn(future.map(|_| ())
                               .map_err(|_| ()));
        };

        let status_future = sa_rx.for_each(move |s| {
            trace!("Sending status: {:?}", s);
            status.send(s).unwrap();
            Ok(())
        });

        core.run(status_future).unwrap();
    }
}

#[derive(Clone)]
pub struct ResolveTask {
    pub tx: mpsc::Sender<Vec<String>>,
    pub name: String,
    pub qtype: QueryType,
}

impl ResolveTask {
    pub fn resolve(&self, resolver: &TrustDNSResolver, dns: SocketAddr) 
        -> Box<Future<Item=(), Error=ResolverError>>
    {
        let tx = self.tx.clone();

        let future = resolver.resolve(dns, &self.name, self.qtype)
            .and_then(move |result| Ok(tx.send(result).unwrap()));

        Box::new(future)
    }
}