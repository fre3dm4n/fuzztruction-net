mod benchmark;
mod handler;
mod networked_benchmark;
mod patchpoint_inspection;
mod queue;
mod stackmap_parser;
mod test_patchpoints;
mod util;

use anyhow::{anyhow, Context, Result};

use std::env;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use scheduler::logging::{self};

use scheduler::config::{Config, ConfigBuilder};

extern crate clap;
use clap::{value_parser, Arg, ArgMatches, Command};
use scheduler::checks::{check_config, check_system};

use ansi_term::Colour::Red;

const CAMPAIN_DUMP_INTERVAL: Duration = Duration::from_secs(60);

fn parse_args() -> ArgMatches {
    let matches = Command::new("Fuzztruction")
        .version("1.0")
        .author("Nils Bars <nils.bars@rub.de>")
        .author("Moritz Schloegel <moritz.schloegel@rub.de>")
        .subcommand_required(true)
        .arg(
            Arg::new("config")
                .help("Path to the configuration file specifing the generator and consumer of the fuzzing campaign.")
                .value_name("config")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::new("log-level")
                .help("Log verbosity (alternative to --verbosity)")
                .value_name("trace, debug, info, warn, error, off")
                .long("log-level")
                .conflicts_with("verbosity")
                .takes_value(true)
                .required(false)
                .default_value("debug")
                .global(true),
        )
        .arg(
            Arg::new("verbosity")
                .short('v')
                .long("verbosity")
                .required(false)
                .multiple_occurrences(true)
                .conflicts_with("log-level")
                .help("Sets the level of verbosity (alternative to --log-level)")
                .global(true),
        )
        .arg(
            Arg::new("purge")
                .help("Purge any data from previous runs. Must be provided if the workdir exists")
                .long("purge")
                .action(clap::ArgAction::SetTrue)
                .global(true)
        )
        .arg(
            Arg::new("suffix")
                .help("Suffix appended to the workdir path provided via the config file\n(i.e., <WORKDIR>-<SUFFIX>)")
                .long("suffix")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("workdir")
                .help("Use the provided workdir instead of the one specified in the config.")
                .long("workdir")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("log-output")
                .help("Redirect stdout and stderr of the generator and the consumer into a file in the working directory. This is handy for debugging configurations")
                .long("log-output")
                .takes_value(false)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("no-log-output")
                .help("Redirecto the output of the generator and consumer to /dev/null")
                .long("no-log-output")
                .takes_value(false)
                .required(false)
                .conflicts_with("log-output")
                .global(true),
        )
        .subcommand(
            Command::new("fuzz")
                .arg(
                    Arg::new("timeout")
                        .help("Timeout")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("60s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent jobs")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::new("dynamic_job_spawning")
                    .long("dynamic-job-spawning")
                    .help("Depending on the load of the system additional jobs are spawned")
                    .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("benchmark")
                .arg(
                    Arg::new("iter-cnt")
                        .help("Iteration count")
                        .short('i')
                        .long("iter-cnt")
                        .takes_value(true)
                        .default_value("100"),
                )
                .arg(
                    Arg::new("with-mutations")
                        .long("with-mutations")
                        .help("Trace the source target and create mutations (with \x00 masks) for all covered patch points")
                        .takes_value(false)
                )
                .arg(
                    Arg::new("max-mutations")
                        .long("max-mutations")
                        .help("Limit the number of active mutations if --with-mutations is also passed")
                        .takes_value(true)
                        .requires("with-mutations")
                )
                .arg(
                    Arg::new("sink-exec-prop")
                        .long("sink-exec-prop")
                        .help("Propability that the sink is executed. Used to simulate the case when a duplicated outputs is produced by the source.")
                        .takes_value(true)
                        .default_value("1.0")
                )
                .arg(
                    Arg::new("timeout")
                        .help("Timeout")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("1s"),
                )
                .arg(
                    Arg::new("record-pcap")
                        .help("Record the network traffic in a pcap file.")
                        .long("record-pcap")
                        .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("patchpoint")
            .arg(
                Arg::new("id")
                .help("ID's of the to be dumped patch points")
                .action(clap::ArgAction::Append)
                .value_parser(value_parser!(usize))
                .takes_value(true)
                .multiple_values(true)
                .required(false)
                )
        )
        .subcommand(
            Command::new("queue")
            .arg(
                Arg::new("crashes-only")
                    .help("Only list those queue entries that belong to a crash")
                    .long("crashes-only")
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("id")
                .help("ID's of the to be dumped queue entry")
                .action(clap::ArgAction::Append)
                .value_parser(value_parser!(usize))
                .takes_value(true)
                .multiple_values(true)
                .required(false)
                )
        )
        .subcommand(
            Command::new("valgrind")
                .arg(
                    Arg::new("once")
                        .long("once")
                        .help("Run valgrind only once instead of every N seconds")
                        .takes_value(false)
                )
                .arg(Arg::new("input-dirs")
                    .help("Besides processing interesting and crashing inputs, process the provided directory in addition.")
                    .short('i')
                    .takes_value(true)
                    .multiple_occurrences(true)
                    .allow_invalid_utf8(true)
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent valgrind instances")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("llvm-cov")
                .about("Run llvm-cov for each insteresting input found.")
                .arg(
                    Arg::new("timeout")
                        .help("Timeout after that a testcase is considered hanging and skipped in consequence")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("10s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent tracing jobs")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::new("overwrite")
                    .long("overwrite")
                    .help("Rerun the coverage computation and delete previous results, if any")
                    .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("with-post-processing")
                    .long("with-post-processing")
                    .help("Do coverage post processsing")
                    .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("crash-reproduction")
                .about("Mode to reproduce crashes.")
                .arg(
                    Arg::new("timeout")
                        .help("Timeout after that a crash is considered hanging and skipped in consequence")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("10s"),
                )
                .arg(
                    Arg::new("id")
                        .help("Queue entry ID to reproduce")
                        .long("id")
                        .takes_value(true)
                )
                .arg(
                    Arg::new("iterations")
                        .help("Number of iterations to perform in order to trigger the bug.")
                        .long("iterations")
                        .short('i')
                        .takes_value(true)
                )
                .arg(
                    Arg::new("enable-rr")
                    .long("enable-rr")
                    .help("Record the crash using rr. This may fail for some targets.")
                    .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("extract-pcaps")
                .about("Extract pcaps from all queue entries.")
        )

        .subcommand(
            Command::new("aflnet")
                .about("Use AFLNet for fuzzing the consumer application.")
                .arg(
                    Arg::new("timeout")
                        .help("Time after stopping the fuzzing campaign")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("60s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent AFLNet instances. If greater than one, one master is spawned and the remaining workers are slaves")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("stateafl")
                .about("Use StateAfl for fuzzing the consumer application.")
                .arg(
                    Arg::new("timeout")
                        .help("Time after stopping the fuzzing campaign")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("60s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent StateAfl instances. If greater than one, one master is spawned and the remaining workers are slaves")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("sgfuzz")
                .about("Use SGFuzz for fuzzing the consumer application.")
                .arg(
                    Arg::new("timeout")
                        .help("Time after stopping the fuzzing campaign")
                        .short('t')
                        .long("timeout")
                        .takes_value(true)
                        .default_value("60s"),
                )
                .arg(
                    Arg::new("jobs")
                        .help("Number of concurrent SGFuzz instances.")
                        .short('j')
                        .long("jobs")
                        .takes_value(true)
                        .default_value("1"),
                )
        )
        .subcommand(
            Command::new("dump-stackmap")
                .about("Dump the LLVM stackmap (e.g., locations and sizes)")
        )
        .subcommand(
            Command::new("test-patchpoints")
            .about("Test the patchpoints of the source application (for debugging)")
            .arg(
                Arg::new("with-mutations")
                    .long("with-mutations")
                    .help("Trace the source target and create mutations (with \x00 masks) for all covered patch points")
                    .takes_value(false)
            )
        )
        .get_matches();
    matches
}

/// Check whether the workdir already exists and raises an error if --purge
/// was not passed. If this function returns `Ok`, the workdir is empty, but
/// exists.
fn check_workdir(config: &mut Config, matches: &ArgMatches) -> Result<()> {
    let purge_flag = matches.get_flag("purge");

    // We only purge if this is the fuzz or benchmark subcommand.
    let expects_empty_dir = matches!(
        matches.subcommand_name().unwrap_or(""),
        "fuzz" | "benchmark" | "aflnet" | "stateafl" | "sgfuzz"
    );

    // Purge the working directory if requested.
    if config.general.work_dir.exists() && expects_empty_dir {
        if purge_flag {
            std::fs::remove_dir_all(&config.general.work_dir).unwrap_or_else(|_| {
                panic!("Failed to remove workdir {:?}", config.general.work_dir)
            });
            std::fs::create_dir_all(&config.general.work_dir)?;
        } else {
            return Err(anyhow!(
                "Workdir {:?} exists and --purge was not provided!",
                config.general.work_dir
            ));
        }
    }
    Ok(())
}

fn setup_logging(matches: &ArgMatches, config: &scheduler::config::Config) {
    let _logfile = PathBuf::from_str("debug.log").unwrap();
    let log_level = match matches.occurrences_of("verbosity") {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    };
    let log_level = log_level.or_else(|| matches.value_of("log-level")).unwrap();
    std::fs::create_dir_all(&config.general.work_dir).unwrap();
    let mut log_path = config.general.work_dir.clone();
    let log_name = format!("{}.txt", matches.subcommand_name().unwrap_or("log"));
    log_path.push(log_name);
    logging::setup_logger(&log_path, log_level).expect("Failed to setup logger");
    logging::setup_panic_logging();
}

/// Returns a `AtomicBool` that is set to `true` when a SIGTERM or SIGINT is received.
fn register_on_termination_flag() -> Arc<AtomicBool> {
    let termination_requested_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(
        signal_hook::consts::SIGTERM,
        Arc::clone(&termination_requested_flag),
    )
    .expect("Failed to register SIGTERM handler.");
    signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        Arc::clone(&termination_requested_flag),
    )
    .expect("Failed to register SIGINT handler.");
    termination_requested_flag
}

fn main() {
    if let Err(err) = real_main() {
        let err_msg = format!("Unexpected Error: {:#?}", err);
        eprintln!("{}", Red.paint(err_msg));
    }
}

fn real_main() -> Result<()> {
    let matches = parse_args();

    let config_file = matches
        .value_of("config")
        .expect("Failed to provide path to config file");
    let mut config = ConfigBuilder::from_path(config_file).expect("Failed to parse config");

    replace_workdir(&mut config, &matches);

    // Add suffix to the workdir if requested.
    suffix_workdir(&mut config, &matches);

    // Logging is using the workdir, thus the workdir setup must happen before enabling logging.
    check_workdir(&mut config, &matches)?;

    //Now we have a workdir -> setup logging before doing anything else.
    setup_logging(&matches, &config);

    configure_jail(&mut config)?;

    check_config(&config)?;
    check_system()?;

    if matches.is_present("log-output") {
        config.source.log_stdout = true;
        config.source.log_stderr = true;
        config.sink.log_stdout = true;
        config.sink.log_stderr = true;
    } else if matches.is_present("no-log-output") {
        config.source.log_stdout = false;
        config.source.log_stderr = false;
        config.sink.log_stderr = false;
        config.sink.log_stdout = false;
    }

    match matches.subcommand() {
        Some(("benchmark", benchmark_matches)) => {
            let termination_requested_flag = register_on_termination_flag();
            handler::handle_cli_benchmark_subcommand(
                benchmark_matches,
                &config,
                termination_requested_flag,
            );
        }
        Some(("dump-stackmap", _)) => stackmap_parser::dump_stackmap(&config.source.bin_path),
        Some(("test-patchpoints", test_patch_point_matches)) => {
            handler::handle_cli_test_patchpoints_subcommand(&config, test_patch_point_matches);
        }
        Some(("fuzz", fuzz_matches)) => {
            let termination_requested_flag = register_on_termination_flag();
            handler::handle_cli_fuzz_subcommand(fuzz_matches, config, termination_requested_flag);
        }
        Some(("valgrind", valgrind_matches)) => {
            let termination_requested_flag = register_on_termination_flag();
            handler::handle_cli_valgrind_subcommand(
                valgrind_matches,
                &config,
                termination_requested_flag,
            )
            .expect("Failed to run Valgrind");
        }
        Some(("llvm-cov", llvm_cov_matches)) => {
            handler::handle_cli_llvm_cov_subcommand(llvm_cov_matches, &config)
                .expect("Failed to run llvm-cov subcommand");
        }
        Some(("aflnet", matches)) => {
            handler::handle_cli_aflnet_subcommand(matches, &config)
                .expect("Failed to run AFLNet mode");
        }
        Some(("stateafl", matches)) => {
            handler::handle_cli_stateafl_subcommand(matches, &config)
                .expect("Failed to run StateAfl mode");
        }
        Some(("sgfuzz", matches)) => {
            handler::handle_cli_sgfuzz_subcommand(matches, &config)
                .expect("Failed to run SGFuzz mode");
        }
        Some(("patchpoint", patchpoint_matches)) => {
            handler::handle_cli_patchpoint_subcommand(patchpoint_matches, &config)?;
        }
        Some(("queue", patchpoint_matches)) => {
            handler::handle_cli_queue_subcommand(patchpoint_matches, &config)?;
        }
        Some(("crash-reproduction", matches)) => {
            handler::handle_crash_reproduction_subcommand(matches, &config)?;
        }
        Some(("extract-pcaps", matches)) => {
            handler::handle_extract_pcaps_subcommand(matches, &config)?;
        }
        _ => {
            println!("No subcommand specified");
        }
    }
    Ok(())
}

fn suffix_workdir(config: &mut Config, matches: &ArgMatches) {
    let suffix = matches.value_of("suffix");
    if let Some(suffix) = suffix {
        let old_workdir = config.general.work_dir.clone();
        let old_filename = old_workdir
            .file_name()
            .unwrap()
            .to_owned()
            .into_string()
            .unwrap();
        let new_filename = format!("{}-{}", old_filename, suffix);

        let mut new_workdir = old_workdir.parent().unwrap().to_owned();
        new_workdir.push(new_filename);
        config.general.work_dir = new_workdir;
    }
}

fn replace_workdir(config: &mut Config, matches: &ArgMatches) {
    let new_workdir = matches.value_of("workdir");
    if let Some(new_workdir) = new_workdir {
        config.general.work_dir = PathBuf::from_str(new_workdir).unwrap();
    }
}

fn configure_jail(config: &mut Config) -> Result<()> {
    if config.general.jail_drop_to_sudo_callee {
        let uid = env::var("SUDO_UID")
            .context("Failed to get SUDO_UID from environment. Please run via sudo or as root.")?;
        let gid = env::var("SUDO_GID")
            .context("Failed to get SUDO_GID from environment. Please run via sudo or as root")?;
        log::info!("Privileges will be dropped to uid: {uid:?} and gid: {gid:?}");
        config.general.jail_uid = Some(uid.parse().unwrap());
        config.general.jail_gid = Some(gid.parse().unwrap());
    }
    Ok(())
}
