use std::{
    collections::HashSet,
    fs::File,
    hash::Hasher,
    io::{Read, Seek},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, RwLock},
    thread,
    time::Instant,
};

use crate::{
    config::Config,
    constants::{
        CALIBRATION_MEASURE_CYCLES, DEFAULT_CALIBRATION_TIMEOUT, EXECUTION_TIMEOUT_MULTIPLYER,
    },
    mutation_cache_ops::MutationCacheOpsEx,
    networked::{get_consumer, get_producer, Client, Server, WaitForPeerResult},
    sink::{self, AflSink},
    sink_bitmap::Bitmap,
    source::{self, Source},
    trace::Trace,
};

use ahash::AHasher;
use anyhow::{Context, Result};
use byte_unit::n_mib_bytes;
use fuzztruction_shared::{mutation_cache::MutationCache, types::MutationSiteID};
use lazy_static::lazy_static;
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use wait_timeout::ChildExt;

use std::time::Duration;
use thiserror::Error;

use super::{
    common_networked::networked_common_calibration_run,
    queue::{Input, QueueEntry},
    worker::WorkerUid,
    worker_impl::{FuzzingPhase, MutatorType},
};

/// Different types of input that might be use the create new queue entries.
#[allow(dead_code)]
#[derive(Debug)]
pub enum InputType<'a> {
    Input(&'a Arc<Input>),
    Bytes(&'a [u8]),
    Parent(&'a QueueEntry),
}

impl InputType<'_> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            InputType::Input(i) => i.data(),
            InputType::Bytes(b) => b,
            InputType::Parent(e) => e.input_as_ref().data(),
        }
    }
}

#[derive(Debug)]
pub enum ServerRunResult {
    /// The Source is the server.
    Source(source::RunResult),
    /// This Sink is the server.
    Sink(sink::RunResult),
}

// #[derive(Debug)]
// pub enum ClientRunResult {
//     /// The Source is the Client.
//     Source(source::RunResult),
//     /// The Sink is the Client.
//     Sink(sink::RunResult),
// }

#[derive(Debug, Error)]
#[allow(unused)]
pub enum CalibrationError {
    #[error("The target showed varing behavior during source execution.")]
    SourceUnstable(String),
    #[error("The target showed varing behavior during sink execution.")]
    SinkUnstable(String),
    #[error("Error while executing the source target {0:#?}")]
    SourceExecutionFailed(source::RunResult),
    #[error("Error while executing the sink target {0:#?}")]
    SinkExecutionFailed(sink::RunResult),
    #[error("Error while executing the server {0:#?}")]
    ServerExecutionFailed(ServerRunResult),
    // #[error("Error while executing the client {0:#?}")]
    // ClientExecutionFailed(ClientRunResult),
    #[error("Source did not produce any output.")]
    NoSourceOutput,
    #[error("The execution durations varied by an unexpected high degree.")]
    ExecutionDurationVarianceTooHight,
}

#[derive(Debug, Error)]
#[allow(unused)]
pub enum ExecError {
    /// The source failed during execution.
    #[error("Error while executing the source {0:#?}")]
    SourceError(source::RunResult),
    /// The source was successfully executed, but did not produced any output.
    #[error("The source produced no output.")]
    NoSourceOutput,
    /// The source execution was successfull, but we already saw the produced output (hash).
    #[error("Duplicated Output.")]
    DuplicatedOutput,
}

struct TcpDumpInstance {
    pub pcap_file: File,
    pub child: Option<Child>,
}

impl Drop for TcpDumpInstance {
    fn drop(&mut self) {
        // file is a tempfile, thus we do not need to take care of it.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            child
                .wait_timeout(Duration::from_secs(120))
                .expect("Failed to kill tcpdump");
        }
    }
}

fn start_tcpdump(_config: &Config) -> Option<TcpDumpInstance> {
    // let dst_port = config
    //     .server_port()
    //     .expect("Server port not set in the config");

    let pcap_file = match tempfile::tempfile() {
        Ok(path) => path,
        Err(err) => {
            log::warn!("Error while allocating temporary pcap file: {err:#?}");
            return None;
        }
    };

    let mut cmd = Command::new("/usr/bin/tcpdump");
    cmd.stdout(pcap_file.try_clone().unwrap());
    cmd.stderr(Stdio::null());

    cmd.args(["-i", "lo", "-U"]);
    cmd.args(["-w", "-"]);

    let child = match cmd.spawn() {
        Ok(child) => Some(child),
        Err(err) => {
            log::warn!("Failed to run tcpdump: {err:#?}");
            return None;
        }
    };

    // Give tcpflow some time to spin up
    thread::sleep(Duration::from_secs(1));
    Some(TcpDumpInstance { pcap_file, child })
}

/// Produces a new QueueEntry from an input and mutations (that have been previously configured via the soruces mutation cache).
/// While creating the QueueEntry it is tested whether the input parameters (input, mutations) determenstically produce
/// the same coverage and do not cause, e.g., a crash or timeout.
///
/// # Errors:
///
/// CalibrationError
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
pub fn common_calibrate(
    config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    input: &InputType,
    mut virgin_map: Option<&mut Bitmap>,
    finder: Option<WorkerUid>,
    phase: Option<FuzzingPhase>,
    mutator: Option<MutatorType>,
    patch_point: Option<MutationSiteID>,
    is_crash: bool,
    parent: Option<Arc<QueueEntry>>,
) -> Result<QueueEntry> {
    let data = input.bytes();

    let mut sink_input = Vec::<u8>::with_capacity(4096);
    let mut bitmaps = Vec::new();

    let mut tcpdump_instance = start_tcpdump(config);

    // Get the default timeout value.
    let mut default_timeout = parent
        .map(|e| {
            e.avg_exec_duration_raw()
                .mul_f64(EXECUTION_TIMEOUT_MULTIPLYER)
        })
        .unwrap_or(DEFAULT_CALIBRATION_TIMEOUT);

    let mut exec_durations = Vec::with_capacity(CALIBRATION_MEASURE_CYCLES.try_into().unwrap());
    if config.sink.send_sigterm {
        default_timeout *= 2;
    }

    let mut crash_did_not_crash_ctr = 0;

    for _ in 0..CALIBRATION_MEASURE_CYCLES {
        let cycle_start_ts = Instant::now();

        // This will only return Ok(...) if we made it until execution of the sink.
        let sink_res =
            common_calibration_run(config, source, sink, data, default_timeout, &mut sink_input)?;

        log::trace!("calibration run result: {:?}", sink_res);
        match sink_res {
            sink::RunResult::Terminated(..) => {
                if is_crash {
                    crash_did_not_crash_ctr += 1;
                }
            }
            sink::RunResult::Signalled(..) if is_crash => (),
            _ => {
                // Anything else than Terminated is considered a failed calibration.
                return Err(CalibrationError::SinkExecutionFailed(sink_res).into());
            }
        }
        let calibration_round_duration = cycle_start_ts.elapsed();
        if !config.sink.send_sigterm && calibration_round_duration > default_timeout {
            return Err(CalibrationError::ExecutionDurationVarianceTooHight.into());
        }

        exec_durations.push(calibration_round_duration);
        let bitmap = sink.bitmap();
        bitmap.classify_counts();
        bitmaps.push(bitmap.clone());
        if let Some(virgin_map) = &mut virgin_map {
            // this is done for each iteration, such that unstable bits are cleared as well.
            bitmap.has_new_bit(virgin_map);
        }
    }

    // Add some offset to account for variations.
    let timeout = exec_durations.iter().max().unwrap();

    // Check whether the coverage output is deterministic.
    let mut sink_unstable = false;
    if bitmaps
        .iter()
        .map(|map| map.hash32())
        .collect::<HashSet<_>>()
        .len()
        > 1
    {
        if config.sink.allow_unstable_sink {
            log::debug!("Sink is unstable, but this is allowed.");
            sink_unstable = true;
        } else {
            return Err(CalibrationError::SinkUnstable("Varying coverage.".to_owned()).into());
        }
    }

    // We take the hash of the last bitmap, even if this was an unstable run.
    let bitmap = sink.bitmap();
    bitmap.classify_counts();
    let qe_hash = bitmap.hash32();

    let qe_input = match input {
        InputType::Bytes(b) => Input::from_bytes::<&[u8], PathBuf>(b, None),
        InputType::Input(i) => (*i).clone(),
        InputType::Parent(p) => p.input(),
    };

    let mut mc = source.mutation_cache().borrow().try_clone()?;
    let mutation_bytes = unsafe {
        // We are working on a copy of the mutation cache, thus this is safe because
        // there are no pointers into this cache.
        mc.purge_nop_entries();
        mc.save_bytes()
    };

    if let Some(tcpdump_instance) = tcpdump_instance.as_mut() {
        let mut child = tcpdump_instance.child.take().unwrap();
        // Give it some time to record all remaining packages :)
        thread::sleep(Duration::from_secs(2));
        let pidfd = Pid::from_raw(child.id().try_into().unwrap());
        if let Err(err) = kill(pidfd, Signal::SIGTERM) {
            log::warn!("Failed to kill tcpdump: {err:#?}");
        } else {
            match child.wait_timeout(Duration::from_secs(30)) {
                Ok(Some(_)) => (),
                Ok(None) => {
                    // we hit the timeout
                    log::warn!("tcpdump did not terminate in time");
                    if let Err(err) = child.kill() {
                        log::warn!("Failed to send sigkill: {err:#?}");
                    }
                    child
                        .wait_timeout(Duration::from_secs(30))
                        .expect("Failed to kill tcpdump");
                }
                Err(err) => log::warn!("Error while waiting for tcpdump: {err:#?}"),
            }
        }
    }

    let mut pcap = if let Some(tcpdump_instance) = &mut tcpdump_instance {
        let file = &mut tcpdump_instance.pcap_file;
        file.rewind().unwrap();

        let mut buf = Vec::new();
        match file.read_to_end(&mut buf) {
            Ok(size) => {
                log::info!("Recorded a PCAP of size {size} during calibration.");
                Some(buf)
            }
            Err(err) => {
                log::warn!("Failed to read pcap file: {err:#?}");
                None
            }
        }
    } else {
        None
    };

    if pcap
        .as_ref()
        .map(|f| f.len() > n_mib_bytes!(4) as usize)
        .unwrap_or(false)
    {
        log::info!("Recorded pcap is too big, dropping");
        pcap.take();
    }

    let mut qe = QueueEntry::new(
        qe_input,
        Some(&mutation_bytes),
        qe_hash,
        *timeout,
        sink_unstable,
        bitmap,
        finder,
        phase,
        mutator,
        patch_point,
        is_crash,
        pcap,
    );

    if is_crash && crash_did_not_crash_ctr > 0 {
        log::warn!(
            "Crashing queue entry {:?} only crashed {} of {} times during calibration",
            qe.id(),
            CALIBRATION_MEASURE_CYCLES - crash_did_not_crash_ctr,
            CALIBRATION_MEASURE_CYCLES
        );
    }

    if let InputType::Parent(parent) = input {
        qe.set_parent(parent);
    }

    log::trace!("Calibration done: {:#?}", qe);
    Ok(qe)
}

#[inline]
fn common_calibration_run(
    config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    data: &[u8],
    timeout: Duration,
    sink_input: &mut Vec<u8>,
) -> Result<sink::RunResult> {
    if config.target_uses_network() {
        networked_common_calibration_run(config, source, sink, data, timeout)
    } else {
        source.write(data);
        let success = source.run(timeout)?;
        match success {
            source::RunResult::Terminated { .. } => (),
            _ => return Err(CalibrationError::SourceExecutionFailed(success).into()),
        }
        source.read(sink_input);
        if sink_input.is_empty() {
            return Err(CalibrationError::NoSourceOutput.into());
        }

        // Run the sink.
        sink.write(sink_input);
        sink.run(timeout)
    }
}

lazy_static! {
    static ref SEEN_OUTPUT_HASHES: RwLock<HashSet<u64>> = RwLock::new(HashSet::new());
}

#[inline]
pub fn common_run(
    _config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    source_input_bytes: &[u8],
    timeout: Duration,
    scratch_buffer: &mut Vec<u8>,
) -> Result<sink::RunResult> {
    source.write(source_input_bytes);
    let success = source.run(timeout)?;
    match success {
        source::RunResult::Terminated { .. } => (),
        _ => return Err(ExecError::SourceError(success).into()),
    }
    source.read(scratch_buffer);
    if scratch_buffer.is_empty() {
        return Err(ExecError::NoSourceOutput.into());
    }

    let mut hasher = AHasher::default();
    hasher.write(scratch_buffer);
    let h = hasher.finish();

    let seen_hashes_locked_read = SEEN_OUTPUT_HASHES.read().unwrap();
    if seen_hashes_locked_read.contains(&h) {
        return Err(ExecError::DuplicatedOutput.into());
    } else {
        // Upgrade to write lock.
        drop(seen_hashes_locked_read);
        let mut seen_hashes_locked_write = SEEN_OUTPUT_HASHES.write().unwrap();
        seen_hashes_locked_write.insert(h);
    }

    // Run the source.
    sink.write(scratch_buffer);
    sink.run(timeout)
}

#[inline]
pub fn common_trace(
    config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    data: &[u8],
    timeout: Duration,
    sink_input: &mut Vec<u8>,
) -> Result<Trace> {
    let pp = source.get_patchpoints()?;
    let mut trace_mc = MutationCache::from_patchpoints(pp.iter())?;

    let current_mc = source.mutation_cache();
    let mc_backup = current_mc.borrow_mut().try_clone()?;

    unsafe {
        // Safety: There are no pointers into `trace_mc`
        trace_mc.union_and_replace(&current_mc.borrow());
    }

    unsafe {
        // Safety: `common_trace` is called initially on QueueEntry's before they are fuzzed,
        // thus there are no pointers into the mutation cache.
        // Furthermore, the `enable_tracing` call below causes the pointers
        // to be refreshed on the agent side (via a sync message).
        source.mutation_cache_replace(&trace_mc)?;
    }

    let trace_result =
        if config.target_uses_network() {
            let (mut client, mut server) = if config.source.is_server.unwrap() {
                (Client::AflSink(sink), Server::Source(source))
            } else {
                (Client::Source(source), Server::AflSink(sink))
            };

            get_producer(&mut client, &mut server).enable_tracing()?;

            server.spawn(timeout).context("Executing server")?;
            let ret = server
                .wait_until_listening(timeout)
                .context("Waiting for the server to be ready to accept connections")?;
            match ret {
                WaitForPeerResult::Terminated(_)
                | WaitForPeerResult::Signalled(_)
                | WaitForPeerResult::TimedOut => {
                    if config.source.is_server.unwrap() {
                        return Err(CalibrationError::ServerExecutionFailed(
                            ServerRunResult::Source(ret.try_into().unwrap()),
                        )
                        .into());
                    } else {
                        return Err(CalibrationError::ServerExecutionFailed(
                            ServerRunResult::Sink(ret.try_into().unwrap()),
                        )
                        .into());
                    }
                }
                WaitForPeerResult::Ready => (),
            }

            client.spawn(timeout).context("Executing client")?;

            // Wait for the producer to terminate.
            let producer_result = get_producer(&mut client, &mut server)
                .wait_for_child_termination(timeout, false)?;

            // kill the consumer if it is still running
            let consumer = get_consumer(&mut client, &mut server);
            let _consumer_result = consumer.wait_for_child_termination(timeout, true, None)?;

            get_producer(&mut client, &mut server)
                .disable_tracing_and_process_result(producer_result)
        } else {
            source.write(data);
            source.trace(timeout)
        };

    // Restore previous state of the MC.
    unsafe {
        // Safety: We just traced this entry, so there are no pointers pointing into the cache.
        source.mutation_cache_replace(&mc_backup)?;
    }

    if let Ok((run_result, trace)) = trace_result {
        let trace = match run_result {
            source::RunResult::Terminated { .. } => trace,
            _ => {
                return Err(CalibrationError::SourceExecutionFailed(run_result).into());
            }
        };

        source.read(sink_input);
        if !config.target_uses_network() && sink_input.is_empty() {
            return Err(CalibrationError::NoSourceOutput.into());
        }

        Ok(trace)
    } else {
        Err(trace_result.unwrap_err())
    }
}
