use std::sync::mpsc;
use std::thread;
use std::net::SocketAddr;
use std::time::{Instant, Duration};

use tokio_core::reactor::Core;
use futures::Stream;
use futures::Sink;
use futures::stream;
use futures::Future;
use futures::sync::mpsc as future_mpsc;

use crossbeam;
use num_cpus;

use resolve::batch::QueryType;
use resolve::batch::StatusTx;
use resolve::resolver::TrustDNSResolver;
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

    pub fn start(self, status: StatusTx) {
        let tasks_cnt = self.tasks.len();
        let chunk_size = tasks_cnt / self.workers_cnt + 1;
        let qps = CONFIG.read().unwrap().qps() as usize;

        crossbeam::scope(|scope| {
            scope.defer(|| debug!("Exiting crosspbeam scope"));
            let mut trigger = TriggerTimer::new(qps, tasks_cnt);
            
            for chunk in self.tasks.chunks(chunk_size) 
                .map(|chunk| chunk.to_vec()) 
            {
                let trigger_handle = trigger.get_handle();
                let status = status.clone();

                scope.spawn(move || {
                    let thread = thread::current(); 
                    let tname = thread.name()
                        .unwrap_or("Unknown");

                    debug!("Started worker thread ({})", tname);
                    ResolverThread::thread_main(chunk, status, trigger_handle);
                    debug!("Terminated worker thread: ({})", tname);
                });
            }

            let dns = CONFIG.read().unwrap().dns_list().to_vec();
            scope.spawn(move || {
                trigger.thread_main(dns)
            });
        })
    }
}


type TriggerTx = future_mpsc::Sender<SocketAddr>;
type TriggerRx = future_mpsc::Receiver<SocketAddr>;

struct TriggerTimer {
    handles: Vec<TriggerTx>,
    qps: usize,
    triggered: usize,
    tasks_cnt: usize,
}

impl TriggerTimer {
    pub fn new(qps: usize, tasks_cnt: usize) -> Self {
        TriggerTimer {
            handles: vec![],
            qps: qps,
            triggered: 0,
            tasks_cnt: tasks_cnt
        }
    }

    pub fn get_handle(&mut self) -> TriggerRx {
        let (tx, rx) = future_mpsc::channel(self.qps as usize);
        self.handles.push(tx);
        rx
    }

    pub fn thread_main(mut self, dns_list: Vec<SocketAddr>) {
        let duration_second = Duration::from_secs(1);

        while self.triggered < self.tasks_cnt {
            let start = Instant::now();
            self.trigger_qps(&dns_list);
            let end = Instant::now();
            
            let diff = end - start;
            if diff < duration_second {
                thread::sleep(duration_second - diff);
            }
        }
    }

    fn trigger_qps(&mut self, dns_list: &[SocketAddr]) {
        let qps_per_handle = (self.qps as f32 / self.handles.len() as f32).ceil() as u32;
        debug!("Triggering {} requests per thread", qps_per_handle);
        for handle in &mut self.handles {
            for i in 0..qps_per_handle {
                let dns = dns_list[i as usize % dns_list.len()];
                handle.send(dns).wait().unwrap();
                self.triggered += 1;
            }
        }
    }
}

struct ResolverThread;
impl ResolverThread {
    fn thread_main(tasks: Vec<ResolveTask>, 
                 status: StatusTx, 
                 task_trigger: TriggerRx) 
    {
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let qps = CONFIG.read().unwrap().qps();

        let future = {
            let resolver = TrustDNSResolver::new(handle.clone(), status);

            stream::iter::<_,_,_>(tasks.into_iter().map(|x| Ok(x)))
                .zip(task_trigger).map(move |(task, dns)| 
                    task.resolve(&resolver, dns).map_err(|_| ()))
                .buffer_unordered(qps as usize)
                .collect()
        };

        core.run(future).unwrap();
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