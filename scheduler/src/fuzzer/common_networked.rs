use anyhow::{Context, Result};

use std::time::{Duration, Instant};

use crate::{
    config::Config,
    fuzzer::common::CalibrationError,
    networked::{get_consumer, get_producer, Client, Server, WaitForPeerResult},
    sink::{self, AflSink},
    source::Source,
};

use super::common::ExecError;

pub fn networked_common_calibration_run(
    config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    _data: &[u8],
    timeout: Duration,
) -> Result<sink::RunResult> {
    let (mut client, mut server) = if config.source.is_server.unwrap() {
        (Client::AflSink(sink), Server::Source(source))
    } else {
        (Client::Source(source), Server::AflSink(sink))
    };

    server.spawn(timeout).context("Executing server")?;
    let start_ts = Instant::now();
    let ret = server
        .wait_until_listening(timeout)
        .context("Waiting for the server to be ready to accept connections")?;
    log::trace!("wait_until_listening took {:?}", start_ts.elapsed());

    match ret {
        WaitForPeerResult::Terminated(_)
        | WaitForPeerResult::Signalled(_)
        | WaitForPeerResult::TimedOut => {
            return Err(CalibrationError::SourceExecutionFailed(ret.try_into().unwrap()).into());
        }
        WaitForPeerResult::Ready => log::trace!("Server is ready to accept connections"),
    }

    client.spawn(timeout).context("Executing client")?;

    let ret = client.wait_until_connect(timeout)?;
    match ret {
        WaitForPeerResult::Terminated(_)
        | WaitForPeerResult::Signalled(_)
        | WaitForPeerResult::TimedOut => {
            log::trace!("Client failed to connect to server");
            let err = Err(CalibrationError::SinkExecutionFailed(
                ret.try_into().unwrap(),
            ));
            // kill the server
            let _ = server.wait_for_child_termination(timeout, true)?;
            return err.context("Client failed to connect to server");
        }
        WaitForPeerResult::Ready => (),
    }

    let start_ts = Instant::now();
    let consumer = get_consumer(&mut client, &mut server);

    let consumer_result = consumer.wait_for_child_termination(timeout, false, None)?;
    log::trace!(
        "wait_for_child_termination of consumer took {:?}",
        start_ts.elapsed()
    );

    // Consumer terminated. Now kill the producer (if still running) and wait for it to terminate.
    get_producer(&mut client, &mut server).wait_for_child_termination(timeout, true)?;

    Ok(consumer_result)
}

pub fn networked_common_run(
    config: &Config,
    source: &mut Source,
    sink: &mut AflSink,
    timeout: Duration,
) -> Result<sink::RunResult> {
    let (mut client, mut server) = if config.source.is_server.unwrap() {
        (Client::AflSink(sink), Server::Source(source))
    } else {
        (Client::Source(source), Server::AflSink(sink))
    };

    server.spawn(timeout).context("Executing server")?;
    let ret = server
        .wait_until_listening(timeout)
        .context("Waiting for the server to be ready to accept connections")?;
    match ret {
        WaitForPeerResult::Terminated(_)
        | WaitForPeerResult::Signalled(_)
        | WaitForPeerResult::TimedOut => {
            // In every of these cases, the source never got ready for accepting a client, so we are treading this
            // like a source that did not produce any output -> ExecError::NoSourceOutput.
            return Err(ExecError::NoSourceOutput.into());
        }
        WaitForPeerResult::Ready => log::trace!("Server is ready to accept connections"),
    }

    client.spawn(timeout).context("Executing client")?;
    let ret = client.wait_until_connect(timeout)?;
    match ret {
        WaitForPeerResult::Terminated(_)
        | WaitForPeerResult::Signalled(_)
        | WaitForPeerResult::TimedOut => {
            log::trace!("Client failed to connect to server");
            let err = Err(ExecError::NoSourceOutput);
            // kill the server
            let _ = server.wait_for_child_termination(timeout, true)?;
            return err.context("Client failed to connect to server");
        }
        WaitForPeerResult::Ready => (),
    }

    let consumer = get_consumer(&mut client, &mut server);
    let consumer_result = consumer.wait_for_child_termination(timeout, false, None)?;

    // Consumer terminated. Now kill the producer (if still running) and wait for it to terminate.
    get_producer(&mut client, &mut server).wait_for_child_termination(timeout, true)?;

    Ok(consumer_result)
}
