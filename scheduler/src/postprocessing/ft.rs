use std::{
    cell::RefCell,
    sync::{
        atomic::{self, AtomicBool},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    config::Config,
    fuzzer::queue::{Queue, QueueEntry, QueueEntryId},
    networked::{configure_tcpdump, get_consumer, get_producer, Client, Server, WaitForPeerResult},
    sink::AflSink,
    source::Source,
};

use anyhow::Result;
use fuzztruction_shared::mutation_cache::MutationCache;
use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};

unsafe fn load_mutations(source: &mut Source, entry: &QueueEntry) -> Result<()> {
    let mutations = entry.mutations();

    if let Some(data) = mutations {
        let mut new_mc = MutationCache::new()?;
        new_mc.load_bytes(data)?;
        source.mutation_cache_replace(&new_mc)?;
    } else {
        // No mutations attached, just clear the mutation cache content.
        let mc_ref = &source.mutation_cache();
        let mut cache = RefCell::borrow_mut(mc_ref);
        cache.clear();
    }

    Ok(())
}

pub fn ft_reproduce_crashes(
    config: &Config,
    exit_requested: Arc<AtomicBool>,
    timeout: Duration,
    target_qe_id: Option<u64>,
    iterations: usize,
    _enable_rr: bool,
) -> Result<()> {
    let tcpdump = configure_tcpdump(config, Some(format!("id:{}", target_qe_id.unwrap())), true);

    let queue_path = config.general.queue_path();
    log::info!("Loading queue at {queue_path:?} from disk...");
    let queue = if let Some(target_qe_id) = target_qe_id {
        Queue::load(&queue_path, Some(&[target_qe_id]))?
    } else {
        Queue::load(&queue_path, None)?
    };
    log::info!("Queue has {} queue entries", queue.len());

    let crashes = queue.filter(|e| e.is_crash());
    log::info!("Found {} crashing queue entries", crashes.len());

    if let Some(target_qe_id) = target_qe_id {
        log::info!("Reproducing queue entry {}", target_qe_id);
    }

    let target_qe_id = target_qe_id.expect("no id set");
    let target_qe = crashes
        .iter()
        .find(|e| e.id() == QueueEntryId::from(target_qe_id as usize))
        .expect("Failed to find QE with given id");

    let mut source = Source::from_config(config, None, Some("crash-reproduce")).unwrap();
    // let mut sink =
    //     AflSink::from_config_crash_repro(config, None, Some("crash-reproduce"), enable_rr).unwrap();
    let mut sink = AflSink::from_config(config, None, Some("crash-reproduce")).unwrap();
    source.start().expect("Failed to start source");
    sink.start().expect("Failed to start sink");

    let _pp = source.get_patchpoints()?;

    let (mut client, mut server) = if config.source.is_server.unwrap() {
        (Client::AflSink(&mut sink), Server::Source(&mut source))
    } else {
        (Client::Source(&mut source), Server::AflSink(&mut sink))
    };

    let source = get_producer(&mut client, &mut server);
    unsafe {
        load_mutations(source, target_qe)?;
    }
    source.sync_mutations()?;

    for _ in 0..iterations {
        if exit_requested.load(atomic::Ordering::Relaxed) {
            return Ok(());
        }

        let spawn_server_ts = Instant::now();
        server.spawn(timeout).unwrap();
        let ret = server.wait_until_listening(timeout).unwrap();
        match ret {
            WaitForPeerResult::Ready => (),
            _ => {
                log::error!("Server failed to start: {:?}", ret);
                return Ok(());
            }
        }
        log::trace!(
            "Server took {:?} to be ready for connections",
            spawn_server_ts.elapsed()
        );

        client.spawn(timeout).unwrap();
        let ret = client.wait_until_connect(timeout)?;
        match ret {
            WaitForPeerResult::Terminated(_)
            | WaitForPeerResult::Signalled(_)
            | WaitForPeerResult::TimedOut => {
                log::warn!("Client failed to connect to server");
                let _ = server.wait_for_child_termination(timeout, true);
                return Ok(());
            }
            WaitForPeerResult::Ready => (),
        }

        let consumer = get_consumer(&mut client, &mut server);
        let ret = consumer
            .wait_for_child_termination(timeout, false, None)
            .unwrap();
        match ret {
            crate::sink::RunResult::Signalled(_) => {
                log::info!("Success! Consumer crashed: {ret:?}");
                return Ok(());
            }
            crate::sink::RunResult::Terminated(_) => {
                log::warn!("Consumer terminated without crashing: {ret:?}");
            }
            crate::sink::RunResult::TimedOut => {
                log::warn!("Consumer timeout out without crashing: {ret:?}");
            }
        }

        let cov_bitmap = consumer.bitmap();
        cov_bitmap.classify_counts();
        let bytes_set = cov_bitmap.count_bytes_set();
        log::trace!("#covered edges: {bytes_set}");

        // consumer terminated, now wait for the producer.
        let producer_result = get_producer(&mut client, &mut server)
            .wait_for_child_termination(timeout, true)
            .unwrap();
        log::info!("producer result: {:?}", producer_result);
    }

    if let Some(mut tcpdump) = tcpdump {
        thread::sleep(Duration::from_secs(2));
        let child_pid = tcpdump.id();
        let child_pid = Pid::from_raw(child_pid.try_into().unwrap());
        let _ = nix::sys::signal::kill(child_pid, SIGTERM);
        log::info!("Waiting for pcap recorder to terminate");
        tcpdump.wait().unwrap();
    }

    Ok(())
}
