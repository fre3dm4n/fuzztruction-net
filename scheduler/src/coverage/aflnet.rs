use std::{
    cmp,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};

use crate::{
    config::Config, coverage::write_cov_binary_info, networked::WaitForPeerResult, sink::AflSink,
};
use anyhow::Result;
use glob::glob;
use indicatif::ProgressStyle;
use itertools::Itertools;

use rayon::prelude::*;
use regex::Regex;

pub fn compute_llvm_cov(
    config: &Config,
    exit_requested: Arc<AtomicBool>,
    jobs: usize,
    timeout: Duration,
    overwrite_results: bool,
) -> Result<()> {
    let inputs_glob = format!(
        "{}/**/replayable-queue",
        config.general.aflnet_workdir().to_str().unwrap()
    );
    let input_dirs = glob(&inputs_glob).unwrap();
    let input_dirs: Vec<std::path::PathBuf> = input_dirs.into_iter().flatten().collect_vec();
    let input_dirs_ref = input_dirs.iter().map(|p| p.as_path()).collect::<Vec<_>>();

    compute_llvm_cov_afl_like_inputs(
        config,
        exit_requested,
        jobs,
        timeout,
        overwrite_results,
        input_dirs_ref,
        true,
    )
}

pub(super) fn compute_llvm_cov_afl_like_inputs(
    config: &Config,
    exit_requested: Arc<AtomicBool>,
    _jobs: usize,
    timeout: Duration,
    overwrite_results: bool,
    input_dirs: Vec<&Path>,
    replayable_inputs: bool,
) -> Result<()> {
    let llvm_cov_path = config.general.llvm_cov_directory();
    let id_regex = Regex::new(r"id:([0-9]+)").unwrap();
    let ts_regex = Regex::new(r"ts:([0-9]+)").unwrap();
    let sync_regex = Regex::new(r"^id:([0-9]+),sync:").unwrap();

    if llvm_cov_path.exists() {
        if overwrite_results {
            fs::remove_dir_all(&llvm_cov_path)?;
        } else {
            log::warn!("Found coverage results at {}, pass --overwrite if you want to rerun the coverage computation.", llvm_cov_path.display());
            return Ok(());
        }
    }
    fs::create_dir(&llvm_cov_path)?;

    write_cov_binary_info(config, &llvm_cov_path);

    let transport_type = config.aflnet.as_ref().unwrap().transport_type();
    log::info!("transport_type: {transport_type:?}");

    let mut all_input_files = collect_input_file_paths(input_dirs);

    log::info!("Processing {} input files", all_input_files.len());
    filter_inputs(&mut all_input_files, &ts_regex, sync_regex);

    let progress_bar = indicatif::ProgressBar::new(all_input_files.len() as u64)
        .with_finish(indicatif::ProgressFinish::Abandon);
    progress_bar.set_style(
        ProgressStyle::with_template("{eta_precise}{bar:60.cyan/blue}{pos:>7}/{len:7}").unwrap(),
    );

    let all_input_files = Mutex::new(all_input_files);
    let init_lock = Mutex::new(());

    progress_bar.tick();

    let jobs = 1;
    (0..jobs).into_par_iter().for_each(|id| {
        let mut sink = {
            let _lock = init_lock.lock().unwrap();
            unshare_network_ns(config);
            let mut sink = AflSink::from_config_with_cov(
                config,
                None,
                Some(&format!("coverage-{}", id)),
                true,
            )
            .unwrap();
            sink.start().unwrap();
            sink
        };

        loop {
            if exit_requested.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }

            let input_path = all_input_files.lock().unwrap().pop();
            let input_path = match &input_path {
                Some(input_path) => input_path,
                None => return,
            };
            let input_name = input_path.file_name().unwrap().to_str().unwrap();

            let id_captures = id_regex.captures(input_name).unwrap();
            let id = id_captures.get(1).unwrap().as_str();

            let ts_in_ms = ts_regex.captures(input_name).unwrap();
            let ts_in_ms = ts_in_ms.get(1).unwrap().as_str();

            let content = read_input(input_path, replayable_inputs);

            if let Err(err) = sink.spawn_child() {
                log::error!("Failed to spawn child: {:?}", err);
                continue;
            }

            let server_ready_state = sink.wait_for_server(timeout);
            match server_ready_state {
                Ok(WaitForPeerResult::Ready) => (),
                Ok(state) => {
                    log::error!("Unexpected server state: {:?}", state);
                    wait_for_child(&mut sink, timeout, true, None);
                    continue;
                }
                Err(err) => {
                    log::error!("Server failed to get into accept state: {:?}", err);
                    wait_for_child(&mut sink, timeout, true, None);
                    continue;
                }
            }

            match transport_type {
                crate::config::TransportType::TCP => {
                    let content = content.into_iter().flatten().collect::<Vec<_>>();
                    let content_len = content.len();
                    log::debug!("Writing {content_len} bytes into TCP socket");
                    if let Err(err) = sink.write_tcp(&content) {
                        log::warn!("Error while writing TCP input to server: {:?}", err);
                        // Kill the child and collect it.
                        wait_for_child(&mut sink, timeout, true, None);
                        continue;
                    }
                }
                crate::config::TransportType::UDP => {
                    let packages = content.iter().map(|e| e.as_slice()).collect::<Vec<_>>();
                    if let Err(err) = sink.write_udp(packages.as_slice()) {
                        log::warn!("Error while writing UDP input to server: {:?}", err);
                        // Kill the child and collect it.
                        wait_for_child(&mut sink, timeout, true, None);
                        continue;
                    }
                }
            }

            wait_for_child(&mut sink, timeout, false, Some(timeout / 2));

            let profraw_report_conent = match sink.get_latest_cov_report() {
                Ok(Some(report)) => report,
                Ok(None) => {
                    log::warn!("Report is empty, skipping");
                    continue;
                }
                Err(err) => {
                    log::error!("Error while getting .profraw report: {:?}", err);
                    continue;
                }
            };
            assert_eq!(profraw_report_conent.len(), 1);

            let profraw_name = format!("id:{};ts:{}.profraw", id, ts_in_ms);
            let mut profraw_path = llvm_cov_path.clone();

            // We are getting the master/queue prefix here, thus we can use it for the destination path
            // to avoid collisions of profraw files with that same name.
            let mut components = input_path.components().rev().skip(1).take(2).collect_vec();
            components.reverse();

            profraw_path.extend(components);
            fs::create_dir_all(&profraw_path).unwrap();

            profraw_path.push(profraw_name);

            fs::write(profraw_path, profraw_report_conent.first().unwrap()).unwrap();

            progress_bar.inc(1);
        }
    });

    Ok(())
}

fn read_input(input_path: &PathBuf, replayable_inputs: bool) -> Vec<Vec<u8>> {
    let mut content = fs::read(input_path).unwrap();
    if !replayable_inputs {
        return vec![content];
    }

    let mut packages = Vec::new();

    while !content.is_empty() {
        let len = u32::from_le_bytes(content.drain(0..4).as_slice().try_into().unwrap());
        let package = content.drain(0..len as usize).as_slice().to_vec();
        packages.push(package);
    }

    packages
}

fn wait_for_child(
    sink: &mut AflSink,
    timeout: Duration,
    kill_child: bool,
    issue_sigterm_after: Option<Duration>,
) {
    if let Err(err) = sink.wait_for_child_termination(timeout, kill_child, issue_sigterm_after) {
        log::error!("Error while waiting for server to terminate: {:?}", err);
    }
}

fn filter_inputs(all_input_files: &mut Vec<PathBuf>, ts_regex: &Regex, sync_regex: Regex) {
    let inputs_before_filtering = all_input_files.len();
    remove_duplicates(all_input_files, ts_regex, sync_regex);
    let inputs_after_filtering = all_input_files.len();
    let removed = inputs_before_filtering - inputs_after_filtering;
    log::info!(
        "Remove {removed} of {inputs_before_filtering} input files because they are duplicates"
    );
}

fn collect_input_file_paths(input_dirs: Vec<&Path>) -> Vec<PathBuf> {
    let mut all_input_files = Vec::new();
    for d in input_dirs {
        let inputs_glob = format!("{}/*", d.to_str().unwrap());
        let input_files = glob(&inputs_glob).unwrap();
        let input_files: Vec<std::path::PathBuf> = input_files
            .into_iter()
            .flatten()
            .filter(|p| p.is_file())
            .collect_vec();
        all_input_files.extend(input_files);
    }
    all_input_files
}

fn remove_duplicates(input_files: &mut Vec<PathBuf>, ts_regex: &Regex, sync_regex: Regex) {
    let mut input_to_discovery_ts = HashMap::<String, u64>::new();
    for input in input_files.iter() {
        let content = fs::read(input).unwrap();
        let content_hash = sha256::digest(&content);

        let input_name = input.file_name().unwrap().to_str().unwrap();
        let ts_in_ms = ts_regex.captures(input_name).unwrap();
        let ts_in_ms = ts_in_ms.get(1).unwrap().as_str().parse().unwrap();

        input_to_discovery_ts
            .entry(content_hash)
            .and_modify(|e| *e = cmp::min(ts_in_ms, *e))
            .or_insert(ts_in_ms);
    }

    input_files.retain(|e| {
        let input_name = e.file_name().unwrap().to_str().unwrap();
        let was_synced = sync_regex.is_match(input_name);
        if was_synced {
            log::info!("Skipping {input_name}, since it was synced from another worker");
            return false;
        }

        let ts_in_ms = ts_regex.captures(input_name).unwrap();
        let current_entry_ts: u64 = ts_in_ms.get(1).unwrap().as_str().parse().unwrap();

        let content = fs::read(e).unwrap();
        let content_hash = sha256::digest(content);
        let lowest_ts = input_to_discovery_ts.get(&content_hash).unwrap();

        if *lowest_ts < current_entry_ts {
            return false;
        }

        true
    });
}

fn unshare_network_ns(_config: &Config) {
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
