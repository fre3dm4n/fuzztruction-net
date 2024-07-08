use std::{
    sync::{self, atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::ArgMatches;

use scheduler::{
    competitors,
    config::Config,
    constants::{
        DYNAMIC_JOB_SPAWNING_CPU_THRESHOLD, DYNAMIC_JOB_SPAWNING_DELAY,
        DYNAMIC_JOB_SPAWNING_INITIAL_DELAY, DYNAMIC_JOB_SPAWNING_MAX_JOBS,
    },
    coverage,
    io_channels::InputChannel,
    postprocessing::{self},
    valgrind,
};
use std::thread;
use sysinfo::System;

use scheduler::fuzzer::campaign::FuzzingCampaign;

use crate::{
    benchmark, networked_benchmark,
    patchpoint_inspection::{self},
    queue, register_on_termination_flag, test_patchpoints,
    util::CliDuration,
    CAMPAIN_DUMP_INTERVAL,
};

pub(crate) fn handle_cli_test_patchpoints_subcommand(
    config: &Config,
    test_patch_point_matches: &ArgMatches,
) {
    test_patchpoints::run(
        config,
        test_patch_point_matches.is_present("with-mutations"),
    )
}

pub(crate) fn handle_cli_fuzz_subcommand(
    fuzz_matches: &ArgMatches,
    config: scheduler::config::Config,
    termination_requested_flag: Arc<AtomicBool>,
) {
    let timeout = fuzz_matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .unwrap()
        .0;

    let mut dynamic_job_spawning = fuzz_matches.get_flag("dynamic_job_spawning");
    let mut last_job_spawned = Instant::now();
    if dynamic_job_spawning {
        log::debug!("Dynamic job spawning is enabled");
    }

    let job_cnt = fuzz_matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();
    let mut campaign = FuzzingCampaign::new(&config).unwrap();
    campaign.start(job_cnt).unwrap();
    log::info!("Fuzzing campaign timeout is set to {:?}", timeout);

    let start_ts = Instant::now();
    let mut last_dump_ts = Instant::now();

    let mut sys_info = System::new();
    sys_info.refresh_cpu();

    while start_ts.elapsed() < timeout {
        if termination_requested_flag.load(sync::atomic::Ordering::SeqCst) {
            log::info!("Termination was requested. Shutting down.");
            break;
        }
        if !campaign.is_any_worker_alive() {
            if !termination_requested_flag.load(sync::atomic::Ordering::SeqCst) {
                log::error!("All workser are dead, but termination was not requested.");
            } else {
                log::info!("All workers terminated. Shutting down.");
            }
            break;
        }

        if let Err(err) = campaign.restart_crashed_worker() {
            log::error!("Error while restarting crashed workers: {err:?}");
        }

        if dynamic_job_spawning
            && start_ts.elapsed() > DYNAMIC_JOB_SPAWNING_INITIAL_DELAY
            && last_job_spawned.elapsed() > DYNAMIC_JOB_SPAWNING_DELAY
        {
            last_job_spawned = Instant::now();
            sys_info.refresh_cpu();
            let cpu_usage = sys_info.global_cpu_info().cpu_usage();
            log::debug!("CPU usage is at {cpu_usage}%");
            if campaign.num_workers() > DYNAMIC_JOB_SPAWNING_MAX_JOBS {
                log::debug!(
                    "Reached maximum of {} jobs, no new jobs are spawned.",
                    DYNAMIC_JOB_SPAWNING_MAX_JOBS
                );
                continue;
            }

            if cpu_usage < DYNAMIC_JOB_SPAWNING_CPU_THRESHOLD {
                log::debug!(
                    "Usage is below {}. Spawning additional worker",
                    DYNAMIC_JOB_SPAWNING_CPU_THRESHOLD
                );
                if let Err(err) = campaign.spawn_additional_worker() {
                    log::error!(
                        "Error while spawning new worker: {err}. Disabling dynamic spawning"
                    );
                    dynamic_job_spawning = false;
                }
            } else {
                log::debug!(
                    "CPU usage is above {}, no further worker is spawned",
                    DYNAMIC_JOB_SPAWNING_CPU_THRESHOLD
                );
            }
        }

        if last_dump_ts.elapsed() > CAMPAIN_DUMP_INTERVAL {
            log::info!("Dumping campaign to disk");
            last_dump_ts = Instant::now();
            if let Err(err) = campaign.dump() {
                log::error!("Dumping failed: {:#?}", err);
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
    if let Err(err) = campaign.shutdown() {
        log::error!("Error while stopping campaign: {:#?}", err);
    }
    campaign.dump().unwrap();
}

pub(crate) fn handle_cli_benchmark_subcommand(
    benchmark_matches: &ArgMatches,
    config: &scheduler::config::Config,
    termination_requested_flag: Arc<AtomicBool>,
) {
    let iter_cnt = benchmark_matches
        .value_of("iter-cnt")
        .map(|e| e.parse().unwrap())
        .unwrap();
    let max_mutations = benchmark_matches
        .value_of("max-mutations")
        .map(|v| v.parse().unwrap());
    let sink_exec_prop = benchmark_matches
        .value_of("sink-exec-prop")
        .map(|v| v.parse().unwrap())
        .unwrap();
    let timeout = benchmark_matches
        .value_of("timeout")
        .map(|v| v.parse::<CliDuration>().unwrap().0)
        .unwrap();

    let with_mutations = benchmark_matches.is_present("with-mutations");

    if matches!(
        config.source.input_type,
        InputChannel::Tcp | InputChannel::Udp
    ) {
        assert!(matches!(
            config.sink.input_type,
            InputChannel::Tcp | InputChannel::Udp
        ));
        networked_benchmark::benchmark_target(
            config,
            iter_cnt,
            timeout,
            termination_requested_flag,
            benchmark_matches,
        )
    } else {
        benchmark::benchmark_target(
            config,
            iter_cnt,
            with_mutations,
            max_mutations,
            sink_exec_prop,
        );
    }
}

pub(crate) fn handle_cli_valgrind_subcommand(
    valgrind_matches: &ArgMatches,
    config: &scheduler::config::Config,
    termination_requested_flag: Arc<AtomicBool>,
) -> Result<()> {
    let input_dirs = valgrind_matches.values_of_lossy("input-dirs");
    let input_dirs = input_dirs
        .unwrap_or_default()
        .into_iter()
        .map(|path| path.into())
        .collect();

    let job_cnt = valgrind_matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap());

    let mut valgrind = valgrind::ValgrindManager::from_config(
        config,
        input_dirs,
        job_cnt,
        termination_requested_flag,
    )?;
    if valgrind_matches.is_present("once") {
        valgrind.queue_new_inputs()?;
        valgrind.run()?;
    } else {
        valgrind.start()?;
    }
    Ok(())
}

pub(crate) fn handle_cli_aflnet_subcommand(matches: &ArgMatches, config: &Config) -> Result<()> {
    let termination_flag = register_on_termination_flag();
    let timeout = matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0)
        .unwrap_or(Duration::from_secs(60));
    let job_cnt: usize = matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();

    competitors::run_aflnet_campaign(config, job_cnt, timeout, termination_flag)?;

    Ok(())
}

pub(crate) fn handle_cli_stateafl_subcommand(matches: &ArgMatches, config: &Config) -> Result<()> {
    let termination_flag = register_on_termination_flag();
    let timeout = matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0)
        .unwrap_or(Duration::from_secs(60));
    let job_cnt: usize = matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();

    competitors::run_stateafl_campaign(config, job_cnt, timeout, termination_flag)?;

    Ok(())
}

pub(crate) fn handle_cli_sgfuzz_subcommand(matches: &ArgMatches, config: &Config) -> Result<()> {
    let termination_flag = register_on_termination_flag();
    let timeout = matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0)
        .unwrap_or(Duration::from_secs(60));
    let job_cnt: usize = matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap();

    competitors::run_sgfuzz_campaign(config, job_cnt, timeout, termination_flag)?;

    Ok(())
}

pub(crate) fn handle_cli_llvm_cov_subcommand(
    trace_matches: &ArgMatches,
    config: &Config,
) -> Result<()> {
    let termination_flag = register_on_termination_flag();
    let timeout = trace_matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0)
        .unwrap();
    let job_cnt = trace_matches
        .value_of("jobs")
        .map(|e| e.parse().unwrap())
        .unwrap_or(1);
    let overwrite_results = trace_matches.get_flag("overwrite");
    let with_post_processsing = trace_matches.get_flag("with-post-processing");

    log::info!("Timeout is set to {timeout:?}");

    if config.target_uses_network() {
        if config.general.aflnet_workdir().exists() {
            log::info!("Found AFLNet working directory");
            coverage::aflnet::compute_llvm_cov(
                config,
                termination_flag.clone(),
                job_cnt,
                timeout,
                overwrite_results,
            )?;
        } else if config.general.stateafl_workdir().exists() {
            log::info!("Found StateAFL working directory");
            coverage::stateafl::compute_llvm_cov(
                config,
                termination_flag.clone(),
                job_cnt,
                timeout,
                overwrite_results,
            )?;
        } else if config.general.sgfuzz_workdir().exists() {
            log::info!("Found SGFuzz working directory");
            coverage::sgfuzz::compute_llvm_cov(
                config,
                termination_flag.clone(),
                job_cnt,
                timeout,
                overwrite_results,
            )?;
        } else {
            log::info!("Found FT working directory");
            coverage::networked::compute_llvm_cov(
                config,
                termination_flag.clone(),
                job_cnt,
                timeout,
                overwrite_results,
            )?;
        }
    } else {
        todo!();
    }

    if termination_flag.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }

    if with_post_processsing {
        coverage::postprocess_llvm_cov(config, termination_flag, job_cnt)?;
    }

    Ok(())
}

pub(crate) fn handle_cli_patchpoint_subcommand(
    patchpoint_matches: &ArgMatches,
    config: &Config,
) -> Result<()> {
    patchpoint_inspection::patchpoint_inspection(config, patchpoint_matches)?;
    Ok(())
}

pub(crate) fn handle_cli_queue_subcommand(matches: &ArgMatches, config: &Config) -> Result<()> {
    queue::queue_cli(config, matches)?;
    Ok(())
}

pub(crate) fn handle_crash_reproduction_subcommand(
    matches: &ArgMatches,
    config: &Config,
) -> Result<()> {
    let termination_flag = register_on_termination_flag();
    let timeout = matches
        .value_of("timeout")
        .map(|e| e.parse::<CliDuration>().unwrap())
        .map(|v| v.0)
        .unwrap();
    let iterations = matches
        .value_of("iterations")
        .map(|e| e.parse().unwrap())
        .unwrap_or(1);

    let target_qe_id: Option<u64> = matches.value_of("id").map(|v| v.parse().unwrap());

    let enable_rr = matches.is_present("enable-rr");

    postprocessing::ft_reproduce_crashes(
        config,
        termination_flag,
        timeout,
        target_qe_id,
        iterations,
        enable_rr,
    )?;
    Ok(())
}

pub(crate) fn handle_extract_pcaps_subcommand(
    _matches: &ArgMatches,
    config: &Config,
) -> Result<()> {
    let termination_flag = register_on_termination_flag();

    postprocessing::extract_pcaps(config, termination_flag)?;
    Ok(())
}
