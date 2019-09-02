use std::cell::Cell;
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use futures::future;
use futures::stream;
use futures::sync::mpsc as future_mpsc;
use futures::Future;
use futures::Sink;
use futures::Stream;
use tokio_core::reactor::Core;

use crossbeam;
use num_cpus;

use config::CONFIG;
use resolve::batch::QueryType;
use resolve::batch::ResolvedTx;
use resolve::batch::StatusTx;
use resolve::error::ResolverError;
use resolve::resolver::TrustDNSResolver;

pub struct ResolverThreadPool {
    tasks: Vec<ResolveTask>,
    workers_cnt: usize,
}

impl ResolverThreadPool {
    pub fn new(num_cpus: usize) -> Self {
        ResolverThreadPool {
            tasks: vec![],
            workers_cnt: num_cpus,
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
        let worker_qps = (qps as f32 / self.workers_cnt as f32).ceil() as usize;

        crossbeam::scope(|scope| {
            scope.defer(|| debug!("Exiting crosspbeam scope"));
            let mut trigger = TriggerTimer::new(tasks_cnt, worker_qps);

            for chunk in self.tasks.chunks(chunk_size).map(|chunk| chunk.to_vec()) {
                let trigger_handle = trigger.get_handle();
                let status = status.clone();

                scope.spawn(move || {
                    let thread = thread::current();
                    let tname = thread.name().unwrap_or("Unknown");

                    debug!("Started worker thread ({})", tname);
                    ResolverThread::thread_main(chunk, status, trigger_handle, worker_qps);
                    debug!("Terminated worker thread: ({})", tname);
                });
            }

            let dns = CONFIG.read().unwrap().dns_list().to_vec();
            scope.spawn(move || {
                debug!("Started qps trigger thread");
                trigger.thread_main(dns);
                debug!("Terminated qps trigger thread");
            });
        })
    }
}

type TriggerTx = future_mpsc::Sender<SocketAddr>;
type TriggerRx = future_mpsc::Receiver<SocketAddr>;

struct TriggerTimer {
    handles: Vec<TriggerTx>,
    worker_qps: usize,
    triggered: Cell<usize>,
    tasks_cnt: usize,
}

impl TriggerTimer {
    pub fn new(tasks_cnt: usize, worker_qps: usize) -> Self {
        TriggerTimer {
            handles: vec![],
            worker_qps: worker_qps,
            triggered: Cell::new(0),
            tasks_cnt: tasks_cnt,
        }
    }

    pub fn get_handle(&mut self) -> TriggerRx {
        let (tx, rx) = future_mpsc::channel(self.worker_qps);
        self.handles.push(tx);
        rx
    }

    pub fn thread_main(mut self, dns_list: Vec<SocketAddr>) {
        let duration_second = Duration::from_secs(1);

        while self.triggered.get() < self.tasks_cnt {
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
        debug!("Triggering {} requests per thread", self.worker_qps);

        // Futures sending request triggers
        let mut send_list = vec![];

        for i in 0..self.worker_qps {
            // Round-Robin dns rotation
            let dns = dns_list[i as usize % dns_list.len()];

            for handle in self.handles.clone() {
                let future = handle.send(dns).and_then(|_| {
                    let old_triggered = self.triggered.get();
                    self.triggered.set(old_triggered + 1);
                    Ok(())
                });
                send_list.push(future);
            }
        }

        future::join_all(send_list).wait().unwrap();
    }
}

struct ResolverThread;
impl ResolverThread {
    fn thread_main(tasks: Vec<ResolveTask>, status: StatusTx, task_trigger: TriggerRx, qps: usize) {
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let future = {
            let resolver = TrustDNSResolver::new(handle.clone(), status);

            // Zipping with stream of triggering messages binds each resolve task launch time
            // to the triggering timer.
            stream::iter::<_, _, _>(tasks.into_iter().map(Ok))
                .zip(task_trigger)
                .map(move |(task, dns)| task.resolve(&resolver, dns).map_err(|_| ()))
                .buffer_unordered(qps)
                .collect()
        };

        core.run(future).unwrap();
    }
}

#[derive(Clone)]
pub struct ResolveTask {
    pub tx: ResolvedTx,
    pub name: String,
    pub qtype: QueryType,
}

impl ResolveTask {
    pub fn resolve(
        &self,
        resolver: &TrustDNSResolver,
        dns: SocketAddr,
    ) -> Box<Future<Item = (), Error = ResolverError>> {
        let tx = self.tx.clone();

        let future = resolver
            .resolve(dns, &self.name, self.qtype)
            .and_then(move |results| {
                for result in results {
                    tx.send(result).unwrap()
                }
                Ok(())
            });

        Box::new(future)
    }
}
