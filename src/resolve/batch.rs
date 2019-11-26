use std::sync::mpsc;
use std::thread;

use resolve::resolver_threadpool::ResolveTask;
use resolve::resolver_threadpool::ResolverThreadPool;

#[derive(Debug, Default, Copy, Clone)]
pub struct Status {
    pub done: u64,
    pub success: u64,
    pub fail: u64,
    pub errored: u64,
    pub running: u64,
}

pub type StatusTx = mpsc::Sender<ResolveStatus>;

#[derive(Copy, Clone, Debug)]
pub enum ResolveStatus {
    Started,
    Success,
    Failure,
    Error,
}

pub type ResolvedTx = mpsc::Sender<(String, String)>;
pub type ResolvedRx = mpsc::Receiver<(String, String)>;

pub struct Batch<I>
where
    I: IntoIterator<Item = String> + 'static,
{
    tasks: Vec<BatchTask<I>>,
    outputs: Vec<ResolvedTx>,
    status_fn: Box<Fn(Status) + Send>,
}

impl<I> Batch<I>
where
    I: IntoIterator<Item = String> + 'static,
{
    pub fn new() -> Self {
        Batch {
            tasks: vec![],
            outputs: vec![],
            status_fn: Box::new(|_| ()),
        }
    }

    pub fn register_status_callback(&mut self, func: Box<Fn(Status) + Send>) {
        self.status_fn = func
    }

    pub fn add_task(&mut self, input: I, output: ResolvedTx, qtype: QueryType) {
        self.tasks.push(BatchTask::new(input, qtype));
        self.outputs.push(output)
    }

    pub fn run(mut self) {
        let tasks_cnt = self.tasks.len();

        let (status_tx, status_rx) = mpsc::channel();

        let mut resolve_pool = ResolverThreadPool::num_cpus();

        // Spawn resolve tasks
        for _ in 0..tasks_cnt {
            let task = self.tasks.pop().unwrap();
            let out = self.outputs.pop().unwrap();

            for name in task.input {
                trace!("Spawning task {} {}", name, task.qtype);
                resolve_pool.spawn(ResolveTask {
                    tx: out.clone(),
                    name: name,
                    qtype: task.qtype,
                });
            }
        }

        let status_fn = self.status_fn;

        // Spawn status thread
        thread::spawn(move || {
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
                            ResolveStatus::Error => status.errored += 1,
                            _ => (),
                        }
                    }
                }
                status_fn(status);
            }
        });

        trace!("Starting resolve job on a thread pool");
        resolve_pool.start(status_tx);
        trace!("Finished resolve");
    }
}

arg_enum! {
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
            QueryType::A => RecordType::A,
            QueryType::AAAA => RecordType::AAAA,
            QueryType::PTR => RecordType::PTR,
            QueryType::NS => RecordType::NS,
        }
    }
}

pub struct BatchTask<I>
where
    I: IntoIterator<Item = String>,
{
    input: I,
    qtype: QueryType,
}

impl<I> BatchTask<I>
where
    I: IntoIterator<Item = String> + 'static,
{
    fn new(input: I, qtype: QueryType) -> Self {
        BatchTask {
            input: input,
            qtype: qtype,
        }
    }
}
