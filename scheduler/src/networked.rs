use anyhow::Result;
use nix::sys::signal::Signal;
use serde::Serialize;
use std::{
    fs,
    process::{Child, Command},
    thread,
    time::Duration,
};

use crate::{
    config::Config,
    io_channels::OutputChannel,
    sink::{self, AflSink},
    source::{self, Source},
};

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum ServerReadySignalKind {
    Bind(usize),
    Listen(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WaitForPeerResult {
    Terminated(i32),
    Signalled(Signal),
    TimedOut,
    Ready,
}

impl TryFrom<WaitForPeerResult> for source::RunResult {
    type Error = &'static str;

    fn try_from(value: WaitForPeerResult) -> std::result::Result<Self, Self::Error> {
        match value {
            WaitForPeerResult::Terminated(exit_code) => Ok(source::RunResult::Terminated {
                exit_code,
                msgs: Vec::new(),
            }),
            WaitForPeerResult::Signalled(signal) => Ok(source::RunResult::Signalled {
                signal,
                msgs: Vec::new(),
            }),
            WaitForPeerResult::TimedOut => Ok(source::RunResult::TimedOut { msgs: Vec::new() }),
            WaitForPeerResult::Ready => Err("Ready state can not be converted"),
        }
    }
}

impl TryFrom<WaitForPeerResult> for sink::RunResult {
    type Error = &'static str;

    fn try_from(value: WaitForPeerResult) -> std::result::Result<Self, Self::Error> {
        match value {
            WaitForPeerResult::Terminated(exit_code) => Ok(sink::RunResult::Terminated(exit_code)),
            WaitForPeerResult::Signalled(signal) => Ok(sink::RunResult::Signalled(signal)),
            WaitForPeerResult::TimedOut => Ok(sink::RunResult::TimedOut),
            WaitForPeerResult::Ready => Err("Ready state can not be converted"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkedRunResult {
    /// The target terminated gracefully.
    Terminated(i32),

    /// The target was terminated by a signal.
    Signalled(Signal),
    /// The target did not manage to finish execution during the given
    /// timeout and was forcefully terminated.
    TimedOut,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Client<'a> {
    Source(&'a mut Source),
    AflSink(&'a mut AflSink),
}
impl Client<'_> {
    pub fn spawn(&mut self, timeout: Duration) -> Result<()> {
        log::trace!("Spawning client");
        match self {
            Client::Source(source) => source.spawn(timeout),
            Client::AflSink(sink) => sink.spawn_child(),
        }
    }

    pub fn wait_until_connect(&mut self, timeout: Duration) -> Result<WaitForPeerResult> {
        match self {
            Client::Source(source) => {
                let source_uses_tcp = source.config().source.output_type == OutputChannel::Tcp;
                if !source.config().source.is_server.unwrap_or(false) && source_uses_tcp {
                    source.wait_until_connect(timeout)
                } else {
                    Ok(WaitForPeerResult::Ready)
                }
            }
            Client::AflSink(_) => {
                // not implemented yet
                Ok(WaitForPeerResult::Ready)
            }
        }
    }

    pub fn wait_for_child_termination(
        &mut self,
        timeout: Duration,
        kill_child: bool,
    ) -> Result<NetworkedRunResult> {
        match self {
            Client::Source(source) => source
                .wait_for_child_termination(timeout, kill_child)
                .map(|v| v.into()),
            Client::AflSink(sink) => sink
                .wait_for_child_termination(timeout, kill_child, None)
                .map(|v| v.into()),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Server<'a> {
    Source(&'a mut Source),
    AflSink(&'a mut AflSink),
}
impl Server<'_> {
    pub fn wait_until_listening(&mut self, timeout: Duration) -> Result<WaitForPeerResult> {
        log::trace!("Waiting for server to accept connections");
        let ret = match self {
            Server::Source(source) => source.wait_until_listening(timeout),
            Server::AflSink(afl_sink) => afl_sink.wait_for_server(timeout),
        };
        log::trace!("Server accept ret: {ret:?}");
        ret
    }

    pub fn spawn(&mut self, timeout: Duration) -> Result<()> {
        log::trace!("Spawning server");
        match self {
            Server::Source(source) => source.spawn(timeout),
            Server::AflSink(afl_sink) => afl_sink.spawn_child(),
        }
    }

    pub fn wait_for_child_termination(
        &mut self,
        timeout: Duration,
        kill_child: bool,
    ) -> Result<NetworkedRunResult> {
        match self {
            Server::Source(source) => source
                .wait_for_child_termination(timeout, kill_child)
                .map(|v| v.into()),
            Server::AflSink(sink) => sink
                .wait_for_child_termination(timeout, kill_child, None)
                .map(|v| v.into()),
        }
    }

    pub fn port(&self, config: &Config) -> Option<String> {
        match self {
            Server::Source(_) => config.source.server_port.clone(),
            Server::AflSink(_) => config.sink.server_port.clone(),
        }
    }
}

pub fn get_consumer<'a>(client: &'a mut Client, server: &'a mut Server) -> &'a mut AflSink {
    if let Client::AflSink(ref mut sink) = client {
        return sink;
    } else if let Server::AflSink(ref mut sink) = server {
        return sink;
    }
    unreachable!()
}

pub fn get_producer<'a>(client: &'a mut Client, server: &'a mut Server) -> &'a mut Source {
    if let Client::Source(ref mut source) = client {
        return source;
    } else if let Server::Source(ref mut source) = server {
        return source;
    }
    unreachable!()
}

pub fn configure_tcpdump(
    config: &Config,
    prefix: Option<String>,
    include_answers: bool,
) -> Option<Child> {
    let dst_port = config
        .server_port()
        .expect("Server port not set in the config");

    let mut pcap_dir = config.general.work_dir.clone();
    pcap_dir.push("pcaps");
    fs::create_dir_all(&pcap_dir).unwrap();

    let mut pcap_path = pcap_dir.clone();
    let mut fname = format!("dst-port-{dst_port}.pcap");
    if let Some(prefix) = prefix {
        fname = format!("{}-{}", prefix, fname);
    }
    pcap_path.push(fname);

    let mut cmd = Command::new("/usr/bin/tcpdump");
    cmd.current_dir(&pcap_dir);
    if include_answers {
        cmd.args(["-v", &format!("port {dst_port}")]);
    } else {
        cmd.args(["-v", &format!("dst port {dst_port}")]);
    }

    cmd.args(["-i", "lo", "-U"]);
    cmd.args(["-w", pcap_path.to_str().unwrap()]);

    let child = Some(cmd.spawn().unwrap());
    // Give tcpflow some time to spin up
    thread::sleep(Duration::from_secs(2));
    child
}
