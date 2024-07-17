use anyhow::{anyhow, Context, Result};

use byte_unit::n_mib_bytes;
use fuzztruction_shared::util::{try_get_child_exit_reason, wait_pid_timeout};
use glob::glob;
use itertools::Itertools;
use lazy_static::lazy_static;
use log::error;
use nix::unistd::{setgid, setuid};

use std::env::{self, set_current_dir};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::prelude::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use std::{
    convert::TryFrom,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    ops::*,
    path::PathBuf,
};
use std::{fs, io, mem};
use thiserror::Error;

use libc::{SIGKILL, SIGTERM, STDIN_FILENO};

use nix::sys::signal::Signal;

use crate::config::Config;
use crate::io_channels::InputChannel;
use crate::networked::{NetworkedRunResult, ServerReadySignalKind, WaitForPeerResult};
use crate::sink_bitmap::{Bitmap, BITMAP_DEFAULT_MAP_SIZE};

use filedescriptor;

const FS_OPT_MAPSIZE: u32 = 0x40000000;

// FDs used by the forkserver to communicate with us.
// Hardcoded in AFLs config.h.
const FORKSRV_FD: i32 = 198;
// Used by the fork server to receive messages.
const AFL_READ_FROM_PARENT_FD: i32 = FORKSRV_FD;
// Used by the fork server to send us messages
const AFL_WRITE_TO_PARENT_FD: i32 = FORKSRV_FD + 1;
// Used by the fork server to send us messages that are specific to our sink impl.
const AFL_FT_WRITE_TO_PARENT_FD: i32 = FORKSRV_FD + 2;

const AFL_SHM_ENV_VAR_NAME: &str = "__AFL_SHM_ID";
const AFL_DEFAULT_TIMEOUT: Duration = Duration::from_millis(10000);

const DEFAULT_TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(120);

static RESERVER_FORKSERVER_FDS_INIT_DONE: Mutex<bool> = Mutex::new(false);

fn open_dev_null() -> i32 {
    let dev_null_fd = unsafe {
        let path = CString::new("/dev/null".as_bytes()).unwrap();
        libc::open(path.as_ptr(), libc::O_RDONLY)
    };
    if dev_null_fd < 0 {
        panic!("Failed to open /dev/null");
    }
    dev_null_fd
}

lazy_static! {
    static ref DEV_NULL_FD: i32 = open_dev_null();
}

/// Reserver the fixed fds ids used to communicate with AFL.
/// If this is not done and we are allocating too many fds, such that we are ending
/// up in the fds id range used by AFL, things get messy if close, dup2, etc. are used on these fds.
fn reserver_forkserver_fds_once() {
    let mut init_done = RESERVER_FORKSERVER_FDS_INIT_DONE.lock().unwrap();
    if !*init_done {
        let path = CString::new("/dev/null".as_bytes()).unwrap();
        let null_fd = unsafe { libc::open(path.as_ptr(), 0) };

        unsafe {
            libc::dup2(null_fd, AFL_READ_FROM_PARENT_FD);
            libc::dup2(null_fd, AFL_WRITE_TO_PARENT_FD);
            libc::dup2(null_fd, AFL_FT_WRITE_TO_PARENT_FD);
            libc::close(null_fd);
        }

        *init_done = true;
    }
}

/// Type used to represent error conditions of the source.
#[derive(Error, Debug)]
pub enum SinkError {
    #[error("The workdir '{0}' already exists.")]
    WorkdirExists(String),
    #[error("Fatal error occurred: {0}")]
    FatalError(String),
    #[error("Exceeded timeout while waiting for data: {0}")]
    CommunicationTimeoutError(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunResult {
    Terminated(i32),
    Signalled(Signal),
    TimedOut,
}

impl From<RunResult> for WaitForPeerResult {
    fn from(val: RunResult) -> Self {
        match val {
            RunResult::Terminated(exit_code) => WaitForPeerResult::Terminated(exit_code),
            RunResult::Signalled(signal) => WaitForPeerResult::Signalled(signal),
            RunResult::TimedOut => WaitForPeerResult::TimedOut,
        }
    }
}

impl From<RunResult> for NetworkedRunResult {
    fn from(val: RunResult) -> Self {
        match val {
            RunResult::Terminated(exit_code) => NetworkedRunResult::Terminated(exit_code),
            RunResult::Signalled(signal) => NetworkedRunResult::Signalled(signal),
            RunResult::TimedOut => NetworkedRunResult::TimedOut,
        }
    }
}

#[derive(Debug)]
pub struct AflSink {
    /// The config of the fuzzing campaign.
    config: Config,
    /// That file system path to the target binary.
    path: PathBuf,
    /// The arguments passed to the binary.
    args: Vec<String>,
    /// Workdir
    #[allow(unused)]
    workdir: PathBuf,
    /// Description of how the target binary consumes fuzzing input.
    input_channel: InputChannel,
    /// The file that is used to pass input to the target.
    input_file: (File, PathBuf),
    /// The session id of the forkserver we are communicating with.
    forkserver_sid: Option<i32>,
    /// The bitmap used to compute coverage.
    bitmap: Bitmap,
    /// The fd used to send data to the forkserver.
    send_fd: Option<i32>,
    /// Non blocking fd used to receive data from the forkserver.
    receive_fd: Option<i32>,
    /// Non blocking fd used to receive data from the forkserver that is specific to our impl and not part of AFL's specification.
    ft_receive_fd: Option<i32>,
    #[allow(unused)]
    stdout_file: Option<(File, PathBuf)>,
    #[allow(unused)]
    stderr_file: Option<(File, PathBuf)>,
    /// Whether to log the output written to stdout. If false, the output is discarded.
    log_stdout: bool,
    /// Whether to log the output written to stderr. If false, the output is discarded.
    log_stderr: bool,
    /// Path where new ASAN reports are stored.
    asan_log_file: PathBuf,
    /// Whether the bitmap was already resized in response of the bitmap size reported by the targets forkserver.
    bitmap_was_resize: bool,
    /// The pid of the child that was forked from the forkserver. None if there is currently no child running.
    child_pid: Option<i32>,
    /// Path where the llvm coverage report is stored if coverage is collected.
    coverage_report: Option<PathBuf>,
    workdir_file_allowlist: Vec<PathBuf>,
    purge_ctr: usize,
    enable_rr: bool,
    bind_ctr: usize,
    listen_ctr: usize,
}

impl AflSink {
    pub fn new(
        path: PathBuf,
        mut args: Vec<String>,
        mut workdir: PathBuf,
        input_channel: InputChannel,
        config: &Config,
        log_stdout: bool,
        log_stderr: bool,
    ) -> Result<AflSink> {
        reserver_forkserver_fds_once();
        workdir.push("sink");

        fs::create_dir_all(&workdir)?;
        set_current_dir(&workdir)?;
        let mut workdir_file_allowlist = Vec::new();

        let (input_file, input_file_path) = create_and_open_file_in(&workdir, "input");
        workdir_file_allowlist.push(input_file_path.clone());

        // Replace the @@ marker in the args with the actual file path (if input type is File).
        if input_channel == InputChannel::File {
            if let Some(elem) = args.iter_mut().find(|e| **e == "@@") {
                *elem = input_file_path.to_str().unwrap().to_owned();
            } else {
                return Err(anyhow!(format!("No @@ marker in args, even though the input channel is defined as file. args: {:#?}", args)));
            }
        }

        let stdout_file = if log_stdout {
            // Setup file for stdout logging.
            let stdout = create_and_open_file_in(&workdir, "stdout");
            workdir_file_allowlist.push(stdout.1.clone());
            Some(stdout)
        } else {
            None
        };

        let stderr_file = if log_stderr {
            // Setup file for stdout logging.
            let stderr = create_and_open_file_in(&workdir, "stderr");
            workdir_file_allowlist.push(stderr.1.clone());
            Some(stderr)
        } else {
            None
        };

        let asan_report_file = create_and_open_file_in(&workdir, "latest-asan-report");
        workdir_file_allowlist.push(asan_report_file.1.clone());

        Ok(AflSink {
            path,
            args,
            workdir,
            input_channel,
            input_file: (input_file, input_file_path),
            forkserver_sid: None,
            bitmap: Bitmap::new_in_shm(BITMAP_DEFAULT_MAP_SIZE, 0x00),
            send_fd: None,
            receive_fd: None,
            ft_receive_fd: None,
            log_stdout,
            log_stderr,
            stdout_file,
            stderr_file,
            asan_log_file: asan_report_file.1,
            config: config.clone(),
            bitmap_was_resize: false,
            child_pid: None,
            coverage_report: None,
            workdir_file_allowlist,
            purge_ctr: 0,
            enable_rr: false,
            bind_ctr: 0,
            listen_ctr: 0,
        })
    }

    pub fn from_config(
        config: &Config,
        id: Option<usize>,
        suffix: Option<&str>,
    ) -> Result<AflSink> {
        let config_new = config.clone();
        let mut workdir = config_new.general.work_dir.clone();

        let mut suffix_builder = id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "0".to_owned());

        if let Some(suffix) = suffix {
            suffix_builder.push('-');
            suffix_builder.push_str(suffix);
        }
        workdir.push(suffix_builder);

        let sink = AflSink::new(
            config_new.sink.bin_path,
            config_new.sink.arguments,
            workdir,
            config_new.sink.input_type,
            config,
            config.sink.log_stdout,
            config.sink.log_stderr,
        )?;
        Ok(sink)
    }

    pub fn from_config_with_cov(
        config: &Config,
        id: Option<usize>,
        suffix: Option<&str>,
        force_clean_exit_on_sigterm: bool,
    ) -> Result<AflSink> {
        let mut config = config.clone();
        let cov_binary = &config
            .sink_cov
            .as_ref()
            .expect("sink-cov not configured in config")
            .bin_path;
        config.sink.bin_path = cov_binary.clone();

        let cov_env = &config
            .sink_cov
            .as_ref()
            .expect("sink-cov not configured in config")
            .env;
        config.sink.env = cov_env.clone();

        if force_clean_exit_on_sigterm {
            // hack to get llvm-cov working for some targets. See afl compiler rt.
            config
                .sink
                .env
                .push(("FT_CLEAN_EXIT_ON_SIGTERM".to_owned(), "1".to_owned()));
        }

        let mut ret = Self::from_config(&config, id, suffix);
        if let Ok(ref mut sink) = ret {
            let mut report_path = sink.workdir.clone();
            report_path.push("coverage-%m.profraw");
            log::info!("report_path={:?}", report_path);
            sink.coverage_report = Some(report_path);
        }
        ret
    }

    pub fn from_config_crash_repro(
        config: &Config,
        id: Option<usize>,
        suffix: Option<&str>,
        enable_rr: bool,
    ) -> Result<AflSink> {
        let mut sink = AflSink::from_config_with_cov(config, id, suffix, false)?;
        sink.enable_rr = enable_rr;
        Ok(sink)
    }

    /// Wait for the given duration for the forkserver read fd to become ready.
    /// Returns Ok(true) if data becomes ready during the given `timeout`, else
    /// Ok(false).
    ///
    /// # Error
    ///
    /// Returns an Error if an unexpected error occurs.
    fn wait_for_data(fds: &[i32], timeout: Duration) -> Result<Vec<i32>> {
        let mut pollfds = Vec::new();
        let mut ready_fds = Vec::new();

        for fd in fds {
            let pollfd = filedescriptor::pollfd {
                fd: *fd,
                events: filedescriptor::POLLIN,
                revents: 0,
            };
            pollfds.push(pollfd);
        }

        let nready = filedescriptor::poll(&mut pollfds, Some(timeout));
        match nready {
            Ok(n) if n > 0 => {
                for pollfd in pollfds {
                    if pollfd.revents == filedescriptor::POLLIN {
                        ready_fds.push(pollfd.fd);
                    }
                }
                if ready_fds.is_empty() {
                    return Err(SinkError::FatalError("Error during sink execution: Poll returned but no fd is ready, this means that some fd got into an unexpected error state".to_string()).into())
                }
                Ok(ready_fds)
            }
            Ok(0) => Err(SinkError::CommunicationTimeoutError(format!(
                "Did not received data after {:?}",
                timeout
            ))
            .into()),
            Ok(n) => {
                unreachable!("Unexpected return value: {}", n);
            }
            Err(ref err) => {
                if let filedescriptor::Error::Poll(err) = err {
                    if err.kind() == io::ErrorKind::Interrupted {
                        return AflSink::wait_for_data(fds, timeout);
                    }
                }
                Err(SinkError::FatalError(format!("Failed to poll fd: {:#?}", err)).into())
            }
        }
    }

    #[allow(unreachable_code)]
    pub fn start(&mut self) -> Result<()> {
        // send_pipe[1](we) -> send_pipe[0](forkserver).
        let send_pipe = [0i32; 2];
        // receive_pipe[1](forkserver) -> receive_pipe[0](we).
        let receive_pipe = [0i32; 2];
        // ft_receive_pipe[1](forkserver) -> ft_receive_pipe[0](we).
        let ft_receive_pipe = [0i32; 2];

        // Create pipe for communicating with the forkserver.
        unsafe {
            let ret = libc::pipe(send_pipe.as_ptr() as *mut i32);
            assert_eq!(ret, 0);
            let ret = libc::pipe(receive_pipe.as_ptr() as *mut i32);
            assert_eq!(ret, 0);
            let ret = libc::pipe(ft_receive_pipe.as_ptr() as *mut i32);
            assert_eq!(ret, 0);
        }

        self.send_fd = Some(send_pipe[1]);
        let child_receive_fd = send_pipe[0];

        self.receive_fd = Some(receive_pipe[0]);
        let child_send_fd = receive_pipe[1];

        self.ft_receive_fd = Some(ft_receive_pipe[0]);
        let ft_child_send_fd = ft_receive_pipe[1];

        let child_pid = unsafe { libc::fork() };
        match child_pid {
            -1 => return Err(anyhow!("Fork failed!")),
            0 => {
                /*
                Child
                Be aware that we are forking a potentially multithreaded application
                here. Since fork() only copies the calling thread, the environment
                might be left in a dirty state because of, e.g., mutexes that where
                locked at the time fork was called.
                Because of this it is only save to call async-signal-safe functions
                (https://man7.org/linux/man-pages/man7/signal-safety.7.html).
                Note that loggin function (debug!...) often internally use mutexes
                to lock the output buffer, thus using logging here is forbidden
                and likely causes deadlocks.
                */
                let map_shm_id = self.bitmap.shm_id();

                unsafe {
                    let ret = libc::setsid();
                    assert!(ret >= 0);
                }

                // Setup args
                let path =
                    self.path.to_str().map(|s| s.to_owned()).ok_or_else(|| {
                        SinkError::Other(anyhow!("Invalid UTF-8 character in path"))
                    })?;
                let path = CString::new(path).unwrap();

                let mut args = self
                    .args
                    .iter()
                    .map(|e| CString::new(e.to_owned()).unwrap())
                    .collect::<Vec<CString>>();
                args.insert(0, path.clone());

                // Setup environment
                let mut envp = Vec::new();
                let shm_env_var =
                    CString::new(format!("{}={}", AFL_SHM_ENV_VAR_NAME, map_shm_id)).unwrap();
                envp.push(shm_env_var);

                let mut env_from_config = Vec::new();
                self.config.sink.env.iter().for_each(|var| {
                    env_from_config
                        .push(CString::new(format!("{}={}", var.0, var.1).as_bytes()).unwrap())
                });

                let afl_maps_size =
                    CString::new(format!("AFL_MAP_SIZE={}", self.bitmap().size())).unwrap();
                envp.push(afl_maps_size);

                // ASAN config
                let asan_log_path = format!(
                    "log_path={}",
                    self.asan_log_file.as_path().to_str().unwrap()
                );
                let asan_options = [
                    "abort_on_error=1",
                    "symbolize=1",
                    "detect_leaks=0",
                    "handle_abort=2",
                    "handle_segv=2",
                    "handle_sigbus=2",
                    "handle_sigill=2",
                    "detect_stack_use_after_return=0",
                    "detect_odr_violation=0",
                    &asan_log_path,
                ];

                let asan_options = format!("ASAN_OPTIONS={}", asan_options.join(":"));

                let asan_options = CString::new(asan_options).unwrap();
                envp.push(asan_options);

                let llvm_cov_env = if let Some(coverage_report) = &self.coverage_report {
                    let ret = format!("LLVM_PROFILE_FILE={}", coverage_report.to_str().unwrap());
                    Some(CString::new(ret).unwrap())
                } else {
                    None
                };

                if let Some(llvm_cov_env) = &llvm_cov_env {
                    envp.push(llvm_cov_env.to_owned());
                }

                env_from_config.iter().for_each(|e| {
                    envp.push(e.to_owned());
                });

                self.close_stdin_or_connect_to_input_file();

                self.setup_stdout_stderr_logging();

                unsafe {
                    self.dup2_child_fds(child_receive_fd, child_send_fd, ft_child_send_fd);
                }

                unsafe {
                    self.set_fsize_limit();

                    // Disable core dumps
                    disable_core_dumps();

                    // Max AS size.
                    // let mut rlim: libc::rlimit = std::mem::zeroed();
                    // rlim.rlim_cur = n_mib_bytes!(512).try_into().unwrap();
                    // rlim.rlim_max = n_mib_bytes!(512).try_into().unwrap();
                    // let ret = libc::setrlimit(libc::RLIMIT_AS, &rlim as *const libc::rlimit);
                    // assert_eq!(ret, 0);

                    let ret = libc::personality(libc::ADDR_NO_RANDOMIZE as u64);
                    assert_eq!(ret, 0);
                }

                if !self.enable_rr {
                    if let Err(_err) = self.drop_privileges() {
                        panic!();
                    }
                }

                if let Some(ref working_dir) = self.config.sink.working_dir {
                    env::set_current_dir(working_dir).unwrap();
                }

                // Make sure that UID == EUID, since if this is not the case,
                // ld will ignore LD_PRELOAD which we need to use for targets
                // that normally load instrumented libraries during runtime.
                assert_eq!(nix::unistd::getuid(), nix::unistd::geteuid());
                assert_eq!(nix::unistd::getegid(), nix::unistd::getegid());

                if self.enable_rr {
                    let path = CString::new("/usr/bin/rr").unwrap();

                    let mut new_args = vec![
                        CString::new("/usr/bin/rr").unwrap(),
                        CString::new("record").unwrap(),
                        //CString::new("-h").unwrap(),
                        CString::new("--disable-cpuid-features-ext").unwrap(),
                        CString::new("0xdc230000,0x2c42,0xc").unwrap(),
                        CString::new("--").unwrap(),
                    ];

                    new_args.extend(args.clone());

                    nix::unistd::execve(&path, &new_args, &envp).expect("execve failed");
                } else {
                    nix::unistd::execve(&path, &args, &envp).expect("execve failed");
                }
            }
            _ => { /* The parent */ }
        }

        /* The parent */
        log::info!("Forkserver has pid {}", child_pid);

        // Note th sid, thus we can kill the child later.
        // This is a sid since the child calls setsid().
        self.forkserver_sid = Some(child_pid);

        // Close the pipe ends used by the child.
        unsafe {
            libc::close(child_receive_fd);
            libc::close(child_send_fd);
            libc::close(ft_child_send_fd);
        }

        // Make that further forks do not inherit our pipe ends (depending on number of workers this will lead to fd exhaustion)
        unsafe {
            libc::fcntl(self.send_fd.unwrap(), libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(self.receive_fd.unwrap(), libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(self.ft_receive_fd.unwrap(), libc::F_SETFD, libc::FD_CLOEXEC);
        }

        // Wait for for hello from the child.
        AflSink::wait_for_data(&[self.receive_fd.unwrap()], AFL_DEFAULT_TIMEOUT)
            .context("Timeout while waiting for forkserver to come up.")?;

        // Read the available data.
        let buffer = [0u8; 4];
        unsafe {
            let ret = libc::read(
                self.receive_fd.unwrap(),
                buffer.as_ptr() as *mut libc::c_void,
                4,
            );
            if ret != 4 {
                return Err(anyhow!(format!(
                    "Failed to do handshake with forkserver. ret={}",
                    ret
                )));
            }

            // Process extended attributes used by AFL++.
            // Sett src/afl-forkserver.c:689 (afl_fsrv_start)
            let status = u32::from_ne_bytes(buffer);
            log::info!("Forkserver status: 0x{:x}", status);
            if status & FS_OPT_MAPSIZE == FS_OPT_MAPSIZE {
                log::info!("Got extended option FS_OPT_MAPSIZE from forkserver");
                let new_map_size = ((status & 0x00fffffe) >> 1) + 1;
                log::info!("Target requests a map of size {} bytes", new_map_size);
                log::info!("Current map size is {} bytes", self.bitmap().size());
                if self.bitmap_was_resize {
                    log::info!("Already resized, skipping....");
                    return Ok(());
                }

                let new_map_size = new_map_size.next_power_of_two() as usize;
                if new_map_size > self.bitmap().size() {
                    log::info!(
                        "Resizing bitmap to {} bytes (nearest power of two)",
                        new_map_size
                    );
                    self.stop();
                    let new_map = Bitmap::new_in_shm(new_map_size, 0x00);
                    let _ = mem::replace(self.bitmap(), new_map);
                    self.bitmap_was_resize = true;
                    return self.start();
                }
            }
        }

        if self.stdout_file.is_some() {
            // Take the the stdout file thus its fd gets dropped.
            self.stdout_file.take();
        }
        if self.stderr_file.is_some() {
            // Take the the stderr file thus its fd gets dropped.
            self.stderr_file.take();
        }

        // We are ready to fuzz!
        Ok(())
    }

    unsafe fn set_fsize_limit(&mut self) {
        if !self.log_stdout && !self.log_stderr {
            // if we log stderr or stdout, the limit will cause our
            // fuzzer to fail after some time.
            let mut rlim: libc::rlimit = std::mem::zeroed();
            rlim.rlim_cur = n_mib_bytes!(512).try_into().unwrap();
            rlim.rlim_max = n_mib_bytes!(512).try_into().unwrap();
            let ret = libc::setrlimit(libc::RLIMIT_FSIZE, &rlim as *const libc::rlimit);
            assert_eq!(ret, 0);
        }
    }

    unsafe fn dup2_child_fds(
        &mut self,
        child_receive_fd: i32,
        child_send_fd: i32,
        ft_child_send_fd: i32,
    ) {
        libc::close(self.receive_fd.unwrap());
        libc::close(self.ft_receive_fd.unwrap());
        libc::close(self.send_fd.unwrap());
        if child_receive_fd != AFL_READ_FROM_PARENT_FD {
            let ret = libc::dup2(child_receive_fd, AFL_READ_FROM_PARENT_FD);
            assert!(ret >= 0);
            libc::close(child_receive_fd);
        }
        if child_send_fd != AFL_WRITE_TO_PARENT_FD {
            let ret = libc::dup2(child_send_fd, AFL_WRITE_TO_PARENT_FD);
            assert!(ret >= 0);
            libc::close(child_send_fd);
        }
        if ft_child_send_fd != AFL_FT_WRITE_TO_PARENT_FD {
            let ret = libc::dup2(ft_child_send_fd, AFL_FT_WRITE_TO_PARENT_FD);
            assert!(ret >= 0);
            libc::close(ft_child_send_fd);
        }
    }

    fn setup_stdout_stderr_logging(&mut self) {
        if self.log_stdout {
            unsafe {
                let fd = self.stdout_file.as_ref().unwrap().0.as_raw_fd();
                libc::dup2(fd, libc::STDOUT_FILENO);
                libc::close(fd);
            }
        } else {
            unsafe {
                libc::dup2(*DEV_NULL_FD, libc::STDOUT_FILENO);
            }
        }

        if self.log_stderr {
            unsafe {
                let fd = self.stderr_file.as_ref().unwrap().0.as_raw_fd();
                libc::dup2(fd, libc::STDERR_FILENO);
                libc::close(fd);
            }
        } else {
            unsafe {
                libc::dup2(*DEV_NULL_FD, libc::STDERR_FILENO);
            }
        }
    }

    fn close_stdin_or_connect_to_input_file(&mut self) {
        match self.input_channel {
            InputChannel::Stdin => unsafe {
                libc::dup2(self.input_file.0.as_raw_fd(), 0);
            },
            _ => unsafe {
                libc::dup2(*DEV_NULL_FD, STDIN_FILENO);
            },
        }
    }

    fn drop_privileges(&mut self) -> Result<()> {
        if let Some((user, group)) = self.config.general.jail_uid_gid() {
            setgid(group.into()).unwrap();
            setuid(user.into()).unwrap();
        }
        Ok(())
    }

    /// Stops the forksever. Must be called before calling start() again.
    /// It is save to call this function multiple times.
    pub fn stop(&mut self) {
        log::info!("Terminating sink forkserver");

        if let Some(sid) = self.forkserver_sid.take() {
            unsafe {
                libc::close(self.send_fd.unwrap());
                libc::close(self.receive_fd.unwrap());

                let _ret = libc::killpg(sid, SIGTERM);

                match wait_pid_timeout(sid, Some(Duration::from_secs(60))) {
                    Ok(status) => {
                        log::debug!("Sink terminated: {status:?}");
                        return;
                    }
                    Err(err) => log::error!("Sink forkser ignored SIGTERM: {err:?}"),
                }

                let _ret = libc::killpg(sid, SIGKILL);
                match wait_pid_timeout(sid, Some(Duration::from_secs(10))) {
                    Ok(status) => log::debug!("Sink forkserver terminated: {status:?}"),
                    Err(err) => log::error!("Failed to terminated sink forkserver: {err:?}"),
                }
            }
        }
    }

    /// Write the given bytes into the sinks input channel. This function
    /// is only allowed to be called on sinks with InputChannel::Stdin or InputChannel::File
    /// input channel.
    pub fn write(&mut self, data: &[u8]) {
        debug_assert!(
            self.input_channel == InputChannel::Stdin || self.input_channel == InputChannel::File
        );

        self.input_file.0.seek(SeekFrom::Start(0)).unwrap();
        self.input_file.0.set_len(0).unwrap();
        self.input_file.0.write_all(data).unwrap();
        self.input_file.0.seek(SeekFrom::Start(0)).unwrap();
        self.input_file.0.sync_all().unwrap();
    }

    pub fn write_tcp(&self, data: &[u8]) -> Result<()> {
        let config = &self.config;
        assert!(config.sink.is_server.unwrap());
        let port = config.sink.server_port.as_ref().unwrap();

        let address = format!("127.0.0.1:{}", port);
        let mut tcp_client = TcpStream::connect(address)?;

        tcp_client.write_all(data)?;
        tcp_client.flush()?;
        Ok(())
    }

    pub fn write_udp(&self, packages: &[&[u8]]) -> Result<()> {
        let config = &self.config;
        assert!(config.sink.is_server.unwrap());
        let port = config.sink.server_port.as_ref().unwrap();
        let remote = format!("127.0.0.1:{}", port);

        let udp_client = UdpSocket::bind("127.0.0.1:0")?;
        udp_client.connect(remote)?;
        for package in packages {
            udp_client.send(package)?;
        }

        Ok(())
    }

    pub fn run(&mut self, timeout: Duration) -> Result<RunResult> {
        self.spawn_child()?;
        self.wait_for_child_termination(timeout, false, None)
    }

    pub fn spawn_child(&mut self) -> Result<()> {
        self.bitmap().reset();
        self.bind_ctr = 0;
        self.listen_ctr = 0;

        if let Err(err) = self.maybe_purge_orphaned_files() {
            log::warn!("Orphan file purging failed: {err:?}");
        }

        let buffer = [0u8; 4];
        let buf_ptr = buffer.as_ptr() as *mut libc::c_void;

        self.flush_ft_pipe(buf_ptr);

        // Tell the forkserver to fork.
        log::trace!("Requesting fork");
        let ret = unsafe { libc::write(self.send_fd.unwrap(), buf_ptr, 4) };
        if ret != 4 {
            error!("Fork request failed");
            return Err(anyhow!("Failed to write to send_fd: {}", ret));
        }

        log::trace!("Waiting for child pid");
        AflSink::wait_for_data(&[self.receive_fd.unwrap()], AFL_DEFAULT_TIMEOUT)
            .context("Failed to retrive child pid from forkserver")?;
        let ret = unsafe { libc::read(self.receive_fd.unwrap(), buf_ptr, 4) };
        if ret != 4 {
            error!("Failed to retrive child pid");
            return Err(anyhow!("Failed to read from receive_non_blocking_fd"));
        }

        let child_pid = i32::from_le_bytes(buffer);
        log::trace!("Got child pid {}", child_pid);

        if child_pid <= 0 {
            log::error!("Child pid '{}' is invalid", child_pid);
            return Err(anyhow!(
                "Failed to parse child_pid. child_pid={}, bytes={:?}",
                child_pid,
                buffer
            ));
        }

        self.child_pid = Some(child_pid);
        Ok(())
    }

    fn flush_ft_pipe(&mut self, buf_ptr: *mut libc::c_void) {
        // flush aux pipe
        let ft_receive_fd = self.ft_receive_fd.unwrap();
        loop {
            let ret = Self::wait_for_data(&[ft_receive_fd], Duration::from_secs(0));
            if ret.is_ok() {
                log::trace!("Discarding 4 pending bytes");
                let _ = unsafe { libc::read(ft_receive_fd, buf_ptr, 4) };
            } else {
                break;
            }
        }
    }

    pub fn wait_for_server(&mut self, timeout: Duration) -> Result<WaitForPeerResult> {
        let mut buffer = [0u8; 4];
        let child_pid = self.child_pid.expect("spawn_child must be called first");

        log::trace!("Waiting for server beeing ready for connections");
        match AflSink::wait_for_data(
            &[self.receive_fd.unwrap(), self.ft_receive_fd.unwrap()],
            timeout,
        ) {
            Ok(ready_fds) => {
                if ready_fds.contains(&self.receive_fd.unwrap()) {
                    self.handle_child_exit_msg().map(|e| e.into())
                } else if ready_fds.contains(&self.ft_receive_fd.unwrap()) {
                    // Check if the server indicates that it is ready to accept connections
                    let ret = unsafe {
                        libc::read(
                            self.ft_receive_fd.unwrap(),
                            buffer.as_mut_ptr() as *mut _,
                            4,
                        )
                    };
                    if ret != 4 {
                        return Err(anyhow!(
                            "Failed to read server listen/accept/ready message."
                        ));
                    }

                    let ready_signal_kind = self
                        .config
                        .sink
                        .server_ready_on
                        .unwrap_or(ServerReadySignalKind::Listen(0));
                    let child_msg = i32::from_le_bytes(buffer);

                    if child_msg == 1 {
                        self.listen_ctr += 1;
                    } else if child_msg == 2 {
                        self.bind_ctr += 1;
                    }

                    // See consumer/aflpp-consumer/instrumentation/afl-compiler-rt.o.c for the origin of these constants :)
                    if child_msg == 1
                        && ready_signal_kind == ServerReadySignalKind::Listen(self.listen_ctr - 1)
                        || child_msg == 2
                            && ready_signal_kind == ServerReadySignalKind::Bind(self.bind_ctr - 1)
                    {
                        Ok(WaitForPeerResult::Ready)
                    } else {
                        log::trace!(
                            "Got {child_msg}, but we are waiting for {:?}.",
                            ready_signal_kind
                        );
                        self.wait_for_server(timeout)
                    }
                } else {
                    unreachable!("Some if these ready fds are unexpected: {ready_fds:?}");
                }
            }
            Err(err) => {
                log::trace!("Child timed out: {:#?}", err);
                // Kill the child since it appears to have timed out.
                let kill_ret = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child_pid),
                    nix::sys::signal::SIGKILL,
                );
                if let Err(ref err) = kill_ret {
                    // This might just be caused by the fact that the child won the race
                    // and terminated before we killed it.
                    log::trace!("Failed to kill child: {:#?}", err);
                }
                log::trace!("Waiting for termination acknowledgement.");
                if let Err(err) = AflSink::wait_for_data(
                    &[self.receive_fd.unwrap()],
                    DEFAULT_TERMINATION_GRACE_PERIOD,
                )
                .context("Child did not acknowledge termination request")
                {
                    let reason = try_get_child_exit_reason(self.forkserver_sid.unwrap());
                    if reason.is_some() {
                        // make sure nobody is awaiting the sid again.
                        self.forkserver_sid.take();
                    }

                    log::error!(
                        "Exit reason: {:#?}, child_pid={:?}, kill_ret={:?}",
                        reason,
                        child_pid,
                        kill_ret
                    );
                    return Err(err.context(format!("child_exit_reason={:#?}", reason)));
                }

                // Consume exit status.
                let ret = unsafe {
                    libc::read(self.receive_fd.unwrap(), buffer.as_mut_ptr() as *mut _, 4)
                };
                if ret != 4 {
                    log::error!("Expected {} != 4", ret);
                }
                self.child_pid.take();
                Ok(WaitForPeerResult::TimedOut)
            }
        }
    }

    fn handle_child_exit_msg(&mut self) -> Result<RunResult> {
        let mut buffer = [0u8; 4];
        log::trace!("Child should have terminated or be signalled, getting exit status");
        let ret = unsafe { libc::read(self.receive_fd.unwrap(), buffer.as_mut_ptr() as *mut _, 4) };
        if ret != 4 {
            error!("Failed to get exit status");
            return Err(anyhow!("Failed to read child exit message"));
        }

        let child_msg = i32::from_le_bytes(buffer);
        log::trace!("Child send exit message {}", child_msg);

        if libc::WIFEXITED(child_msg) {
            self.child_pid.take();
            Ok(RunResult::Terminated(libc::WEXITSTATUS(child_msg)))
        } else if libc::WIFSIGNALED(child_msg) {
            let signal = libc::WTERMSIG(child_msg);
            let signal = match Signal::try_from(signal) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to parse signal code {}. Error: {:?}. Using dummy signal SIGUSR2",
                        signal, e
                    );
                    // Some dummy signal type.
                    Signal::SIGUSR2
                }
            };
            self.child_pid.take();
            if signal == Signal::SIGTERM {
                // we treat termination via SIGTERM as normal termination.
                Ok(RunResult::Terminated(0))
            } else {
                Ok(RunResult::Signalled(signal))
            }
        } else {
            unreachable!();
        }
    }

    pub fn wait_for_child_termination(
        &mut self,
        timeout: Duration,
        immediately_issue_sigkill: bool,
        mut issue_sigterm_after: Option<Duration>,
    ) -> Result<RunResult> {
        let buffer = [0u8; 4];
        let buf_ptr = buffer.as_ptr() as *mut libc::c_void;
        let child_pid = self.child_pid.expect("spawn_child must be called first");

        if immediately_issue_sigkill {
            log::trace!("killing child since kill_child was set");
            let _kill_ret = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child_pid),
                nix::sys::signal::SIGKILL,
            );
        }

        if self.config.sink.send_sigterm {
            issue_sigterm_after = Some(timeout);
        }

        log::trace!("Waiting for child termination");
        let wait_state = if let Some(delay) = issue_sigterm_after {
            let ret = AflSink::wait_for_data(&[self.receive_fd.unwrap()], delay);
            if ret.is_err() {
                log::trace!("Sending SIGTERM");
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child_pid),
                    nix::sys::signal::SIGTERM,
                );
                AflSink::wait_for_data(&[self.receive_fd.unwrap()], timeout)
            } else {
                ret
            }
        } else {
            AflSink::wait_for_data(&[self.receive_fd.unwrap()], timeout)
        };

        match wait_state {
            Ok(_) => (),
            Err(err) => {
                log::trace!("Child timed out: {:#?}", err);

                if log::log_enabled!(log::Level::Trace) {
                    let mut print_stack_cmd = Command::new("eu-stack");
                    print_stack_cmd.args(["-p", &child_pid.to_string()]);

                    if let Ok(output) = print_stack_cmd.output() {
                        let stdout = String::from_utf8(output.stdout).unwrap();
                        log::trace!("Target stacktrace on timeout:\n{stdout}");
                    }
                }

                log::trace!("Sending SIGKILL");
                // Kill the child since it appears to have timed out.
                let kill_ret = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child_pid),
                    nix::sys::signal::SIGKILL,
                );
                if let Err(ref err) = kill_ret {
                    // This might just be caused by the fact that the child won the race
                    // and terminated before we killed it.
                    log::trace!("Failed to kill child: {:#?}", err);
                }
                if let Err(err) = AflSink::wait_for_data(
                    &[self.receive_fd.unwrap()],
                    DEFAULT_TERMINATION_GRACE_PERIOD,
                )
                .context("Child did not acknowledge termination request")
                {
                    let reason = try_get_child_exit_reason(self.forkserver_sid.unwrap());
                    log::error!(
                        "Exit reason: {:#?}, child_pid={:?}, kill_ret={:?}",
                        reason,
                        child_pid,
                        kill_ret
                    );
                    self.child_pid.take();
                    return Err(err.context(format!("child_exit_reason={:#?}", reason)));
                }

                // Consume exit status.
                let ret = unsafe { libc::read(self.receive_fd.unwrap(), buf_ptr, 4) };
                if ret != 4 {
                    log::error!("Expected {} != 4", ret);
                }

                self.child_pid.take();
                return Ok(RunResult::TimedOut);
            }
        }

        self.handle_child_exit_msg()
    }

    pub fn bitmap(&mut self) -> &mut Bitmap {
        &mut self.bitmap
    }

    pub fn get_latest_asan_report(&self) -> Option<String> {
        let report_path = &self.asan_log_file;
        let reports =
            glob::glob(&format!("{}.*", report_path.as_path().to_str().unwrap())).unwrap();
        let reports = reports.into_iter().flatten().collect_vec();
        if reports.len() > 1 {
            log::warn!("Multiple ASAN reports found")
        }
        if let Some(report) = reports.first() {
            let res = fs::read_to_string(report).unwrap();
            for report in reports {
                fs::remove_file(report).unwrap();
            }
            return Some(res);
        }
        None
    }

    pub fn get_latest_cov_report(&self) -> Result<Option<Vec<Vec<u8>>>> {
        if let Some(cov_report_path) = &self.coverage_report {
            let cov_reports = cov_report_path.to_str().unwrap();
            let cov_reports_glob = cov_reports.replace("%m", "*");
            let cov_reports_glob = glob(&cov_reports_glob).unwrap().flatten();
            let mut res = Vec::new();

            for report in cov_reports_glob {
                let ret = fs::read(&report).unwrap();
                fs::remove_file(report)?;
                res.push(ret);
            }
            if res.is_empty() {
                Ok(None)
            } else {
                Ok(Some(res))
            }
        } else {
            Ok(None)
        }
    }

    // Try to remove all files in the workdir.
    fn maybe_purge_orphaned_files(&mut self) -> Result<()> {
        self.purge_ctr += 1;
        if self.purge_ctr % 1000 != 0 {
            return Ok(());
        }

        let mut delete_ctr = 0usize;
        let dir = fs::read_dir(&self.workdir)?;
        for entry in dir {
            let entry = entry?;
            if !self.workdir_file_allowlist.contains(&entry.path())
                && entry.path() != self.workdir
                && !entry
                    .file_name()
                    .to_str()
                    .unwrap_or(".profraw")
                    .contains(".profraw")
            {
                if entry.path().is_file() {
                    fs::remove_file(entry.path())?;
                    delete_ctr += 1;
                } else if entry.path().is_dir() {
                    fs::remove_dir_all(entry.path())?;
                    delete_ctr += 1;
                }
            }
        }

        log::trace!("Purged {} files from workdir", delete_ctr);
        Ok(())
    }
}

unsafe fn disable_core_dumps() {
    let limit_val: libc::rlimit = std::mem::zeroed();
    let ret = libc::setrlimit(libc::RLIMIT_CORE, &limit_val);
    assert_eq!(ret, 0);
}

fn create_and_open_file_in(workdir: &Path, name: &str) -> (File, PathBuf) {
    let mut path = workdir.to_owned();
    path.push(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    (file, path)
}

impl Drop for AflSink {
    fn drop(&mut self) {
        self.stop();
    }
}
