use std::{
    cell::RefCell,
    fs,
    process::Command,
    sync::{
        atomic::{self, AtomicBool},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    config::Config,
    coverage::write_cov_binary_info,
    fuzzer::queue::{Queue, QueueEntry},
    networked::{get_consumer, get_producer, Client, Server, WaitForPeerResult},
    sink::AflSink,
    source::Source,
};

use anyhow::Result;
use fuzztruction_shared::mutation_cache::MutationCache;
use itertools::Itertools;

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

pub fn compute_llvm_cov(
    config: &Config,
    exit_requested: Arc<AtomicBool>,
    _jobs: usize,
    timeout: Duration,
    overwrite_results: bool,
) -> Result<()> {
    let llvm_traces_folder = config.general.llvm_cov_directory();
    if llvm_traces_folder.exists() {
        if overwrite_results {
            fs::remove_dir_all(&llvm_traces_folder)?;
        } else {
            log::warn!("Found coverage results at {}, pass --overwrite if you want to rerun the coverage computation.", llvm_traces_folder.display());
            return Ok(());
        }
    }
    fs::create_dir(&llvm_traces_folder)?;

    // We need the path to the coverage binary later when processing the coverage raw data,
    // so we dump the path into a file in the results directory.
    write_cov_binary_info(config, &llvm_traces_folder);

    let queue_path = config.general.queue_path();
    log::info!("Loading queue at {queue_path:?} from disk...");
    let queue = Queue::load(&queue_path, None)?;
    log::info!("Tracing {} queue entries", queue.len());

    let mut source = Source::from_config(config, None, Some("llvm-cov")).unwrap();
    //let mut sink = AflSink::from_config(config, None, Some("llvm-cov")).unwrap();
    let mut sink = AflSink::from_config_with_cov(config, None, Some("llvm-cov"), true).unwrap();
    source.start().expect("Failed to start source");
    sink.start().expect("Failed to start sink");

    let _pp = source.get_patchpoints()?;

    let (mut client, mut server) = if config.source.is_server.unwrap() {
        (Client::AflSink(&mut sink), Server::Source(&mut source))
    } else {
        (Client::Source(&mut source), Server::AflSink(&mut sink))
    };

    for entry in queue.iter().sorted_by_key(|q| q.id().0) {
        if exit_requested.load(atomic::Ordering::SeqCst) {
            break;
        }

        log::info!("Processing queue entry {:?}", entry.id());
        let source = get_producer(&mut client, &mut server);
        unsafe {
            load_mutations(source, &entry)?;
        }
        source.sync_mutations()?;

        let spawn_server_ts = Instant::now();
        server.spawn(timeout).unwrap();
        let ret = server.wait_until_listening(timeout).unwrap();
        match ret {
            WaitForPeerResult::Ready => (),
            _ => {
                log::warn!("Server failed to start: {:?}", ret);
                continue;
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
                continue;
            }
            WaitForPeerResult::Ready => (),
        }

        let consumer = get_consumer(&mut client, &mut server);
        let ret = consumer
            .wait_for_child_termination(timeout, false, Some(timeout))
            .unwrap();
        log::info!("consumer result: {ret:?}");

        let cov_bitmap = consumer.bitmap();
        cov_bitmap.classify_counts();
        let bytes_set = cov_bitmap.count_bytes_set();
        log::trace!("#covered edges: {bytes_set}");

        let cov_hash = cov_bitmap.hash32();
        let expected_hash = entry.bitmap_hash32();
        if cov_hash != expected_hash {
            log::trace!("cov_hash != expected_hash ({cov_hash} vs. {expected_hash})");
        }

        let cov_edges = cov_bitmap.count_bytes_set() as f64;
        let expected_cov_edges = entry.covered_edges().count_bits_set() as f64;
        let cov_ratio = 1f64 - (cov_edges / expected_cov_edges);
        if cov_ratio.abs() > 0.1 {
            log::warn!("Coverage fluctuation unusually high (covered {cov_edges} edges but expected {expected_cov_edges})");
        }

        if let Some(reports) = consumer.get_latest_cov_report()? {
            let tmp_dir = tempfile::tempdir().unwrap();
            let mut src_files = Vec::new();
            for (id, report) in reports.iter().take(1).enumerate() {
                let mut dst = tmp_dir.path().to_owned();
                dst.push(format!("{}", id));
                fs::write(&dst, report).unwrap();
                src_files.push(dst.to_str().unwrap().to_owned());
            }

            let report_name = format!(
                "id:{};ts:{}.profraw",
                entry.id().0,
                entry.creation_ts().unwrap()
            );
            let mut dst = llvm_traces_folder.clone();
            dst.push(report_name);

            let mut cmd = Command::new("llvm-profdata");
            cmd.args(["merge", "-sparse"]);
            cmd.args(src_files);
            cmd.args(["-o", dst.to_str().unwrap()]);

            cmd.spawn().unwrap().wait().unwrap();

            //fs::write(dst, report)?;
        } else {
            log::error!("Failed to get coverage report for {:?}", entry.id());
        }

        // consumer terminated, now wait for the producer.
        let producer_result = get_producer(&mut client, &mut server)
            .wait_for_child_termination(timeout, true)
            .unwrap();
        log::info!("producer result: {:?}", producer_result);
    }

    Ok(())
}
