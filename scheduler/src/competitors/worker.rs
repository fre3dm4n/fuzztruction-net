use anyhow::anyhow;
use anyhow::Result;
use std::{
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::config::Config;

use super::aflnet::AflNetWorker;
use super::sgfuzz::SGFuzzWorker;
use super::stateafl::StateAflWorker;

#[derive(Debug, Clone, Copy)]
pub enum WorkerId {
    Master,
    Slave(usize),
}

#[derive(Debug)]
pub struct WorkerProxy {
    handle: JoinHandle<()>,
}

impl WorkerProxy {
    pub fn new(handle: JoinHandle<()>) -> Self {
        WorkerProxy { handle }
    }

    pub fn join(self, timeout: Option<Duration>) -> Result<()> {
        let start_ts = Instant::now();
        loop {
            if self.handle.is_finished() {
                self.handle.join().unwrap();
                return Ok(());
            }
            if let Some(timeout) = timeout {
                if start_ts.elapsed() > timeout {
                    return Err(anyhow!("Thread did not terminate after {:?}", timeout));
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

pub(super) fn unshare_network_namespace(_config: &Config) {
    log::info!("Unsharing network namespace");
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert!(ret == 0);

    let ret = process::Command::new("ip")
        .args(["link", "set", "dev", "lo", "up"])
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    log::info!("ip ret: {:?}", ret);
}

fn run_campaign<F: Fn(WorkerId) -> WorkerProxy>(
    _config: &Config,
    job_cnt: usize,
    timeout: Duration,
    termination_flag: Arc<AtomicBool>,
    worker_factory: F,
) -> Result<()> {
    let mut workers = Vec::new();

    for job_id in 0..job_cnt {
        thread::sleep(Duration::from_secs(1));

        let id = match job_id {
            0 => WorkerId::Master,
            id => WorkerId::Slave(id),
        };

        let proxy = worker_factory(id);
        workers.push(proxy);
    }

    // Wait for timeout
    log::info!("Waiting for {timeout:?} until terminating workers");
    let start_ts = Instant::now();

    loop {
        thread::sleep(Duration::from_millis(100));
        if start_ts.elapsed() > timeout {
            log::info!("Time is up, terminating workers");
            // If we got triggered by the timeout, we need to notify the workers that they should terminate now.
            termination_flag.store(true, Ordering::SeqCst);
            break;
        }
        if termination_flag.load(Ordering::SeqCst) {
            log::info!("Run was canceled");
            break;
        }
    }

    log::info!("Waiting for all workers to terminate");
    for worker in workers {
        worker.join(None)?;
    }

    Ok(())
}

pub fn run_aflnet_campaign(
    config: &Config,
    job_cnt: usize,
    timeout: Duration,
    termination_flag: Arc<AtomicBool>,
) -> Result<()> {
    let termination_worker_flag = Arc::clone(&termination_flag);
    let worker_factory = |id| {
        let worker = AflNetWorker::new(id, config, termination_worker_flag.clone());
        worker.run()
    };

    run_campaign(config, job_cnt, timeout, termination_flag, worker_factory)
}

pub fn run_stateafl_campaign(
    config: &Config,
    job_cnt: usize,
    timeout: Duration,
    termination_flag: Arc<AtomicBool>,
) -> Result<()> {
    let termination_worker_flag = Arc::clone(&termination_flag);
    let worker_factory = |id| {
        let worker = StateAflWorker::new(id, config, termination_worker_flag.clone());
        worker.run()
    };

    run_campaign(config, job_cnt, timeout, termination_flag, worker_factory)
}

pub fn run_sgfuzz_campaign(
    config: &Config,
    job_cnt: usize,
    timeout: Duration,
    termination_flag: Arc<AtomicBool>,
) -> Result<()> {
    let termination_worker_flag = Arc::clone(&termination_flag);
    let worker_factory = |id| {
        let worker = SGFuzzWorker::new(id, config, termination_worker_flag.clone());
        worker.run()
    };

    run_campaign(config, job_cnt, timeout, termination_flag, worker_factory)
}
