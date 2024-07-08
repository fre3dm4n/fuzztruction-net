use clap::ArgMatches;
use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};
use scheduler::{
    config::Config,
    networked::{configure_tcpdump, get_consumer, get_producer, Client, Server, WaitForPeerResult},
    sink::{self, AflSink},
    source::Source,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[allow(clippy::too_many_arguments)]
pub fn benchmark_target(
    config: &Config,
    iter_cnt: usize,
    timeout: Duration,
    termination_requested_flag: Arc<AtomicBool>,
    benchmark_matches: &ArgMatches,
) {
    let pacap_recording_cmd = if benchmark_matches.get_flag("record-pcap") {
        configure_tcpdump(config, None, false)
    } else {
        None
    };

    let mut source = Source::from_config(config, None, None).unwrap();
    let mut sink = AflSink::from_config(config, None, None).unwrap();
    source.start().expect("Failed to start source");
    sink.start().expect("Failed to start sink");

    let mut seen_coverage_hashes = HashSet::new();
    let mut seen_edges = HashMap::<usize, usize>::new();

    let (mut client, mut server) = if config
        .source
        .is_server
        .expect("is_server not set for source config")
    {
        (Client::AflSink(&mut sink), Server::Source(&mut source))
    } else {
        (Client::Source(&mut source), Server::AflSink(&mut sink))
    };

    log::info!("Timeout is set to {timeout:?}");
    let start_ts = Instant::now();
    for iteration in 1..=iter_cnt {
        if termination_requested_flag.load(Ordering::SeqCst) {
            break;
        }
        log::info!("\n################ Iteration {iteration} ################");

        let spawn_server_ts = Instant::now();
        server.spawn(timeout).unwrap();
        let ret = server.wait_until_listening(timeout).unwrap();
        match ret {
            WaitForPeerResult::Ready => (),
            _ => {
                log::warn!("Server failed to get into ready state after {timeout:?}: {ret:?}");
                continue;
            }
        }

        log::info!(
            "Server took {:?} to be ready for connections",
            spawn_server_ts.elapsed()
        );

        let client_spawn_ts = Instant::now();
        client.spawn(timeout).unwrap();

        let consumer = get_consumer(&mut client, &mut server);
        let ret = consumer
            .wait_for_child_termination(timeout, false, None)
            .unwrap();

        log::info!("Client took {:?} to terminate.", client_spawn_ts.elapsed());

        log::info!("Consumer result: {ret:#?}");
        match ret {
            sink::RunResult::Terminated(_) => (),
            sink::RunResult::Signalled(signal) => {
                log::warn!("The consumer should typically not be signalled: {signal:?}")
            }
            sink::RunResult::TimedOut => {
                log::warn!("The consumer should typically not timeout")
            }
        }

        let cov_bitmap = consumer.bitmap();
        cov_bitmap.classify_counts();
        let bytes_set = cov_bitmap.count_bytes_set();
        log::info!("#covered edges: {bytes_set}");

        seen_coverage_hashes.insert(cov_bitmap.hash32());
        for edge in cov_bitmap.edges() {
            seen_edges.entry(edge).and_modify(|e| *e += 1).or_insert(1);
        }

        // consumer terminated, now wait for the producer.
        let producer_result = get_producer(&mut client, &mut server)
            .wait_for_child_termination(timeout, false)
            .unwrap();
        log::info!("producer result: {:?}", producer_result);
    }

    let total_duration = start_ts.elapsed();
    let execs = iter_cnt as f64 / total_duration.as_secs_f64();
    log::info!("{execs:.02} execs/s");
    log::info!(
        "{} #coverage hashes in {} iterations",
        seen_coverage_hashes.len(),
        iter_cnt
    );

    let number_of_unstable_edges = seen_edges
        .into_values()
        .filter(|hit_cnt| *hit_cnt != iter_cnt)
        .count();
    log::info!("{number_of_unstable_edges} #edges with unstable hit counts");

    if let Some(mut pacap_recording_cmd) = pacap_recording_cmd {
        // Give it some time to process all captured packages.
        thread::sleep(Duration::from_secs(2));
        let child_pid = pacap_recording_cmd.id();
        let child_pid = Pid::from_raw(child_pid.try_into().unwrap());
        let _ = nix::sys::signal::kill(child_pid, SIGTERM);
        log::info!("Waiting for pcap recorder to terminate");
        pacap_recording_cmd.wait().unwrap();
    }
}
