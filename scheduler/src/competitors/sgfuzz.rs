use std::{
    fs::{self, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};

use crate::config::{Config, TargetExecutionContext};

use super::worker::{unshare_network_namespace, WorkerId, WorkerProxy};

const RESTART_THRESHOLD: usize = 1024;

#[derive(Debug)]
pub(super) struct SGFuzzWorker {
    id: WorkerId,
    config: Config,
    termination_flag: Arc<AtomicBool>,
}

impl SGFuzzWorker {
    pub fn new(id: WorkerId, config: &Config, termination_flag: Arc<AtomicBool>) -> Self {
        SGFuzzWorker {
            id,
            config: config.clone(),
            termination_flag,
        }
    }

    fn spawn(&mut self) -> Child {
        let sgfuzz_cfg = self
            .config
            .sgfuzz
            .as_ref()
            .expect("Target has no sgfuzz config");

        let seed_input_dir = sgfuzz_cfg.input_dir.clone();

        let seed_out_dir = self.config.general.sgfuzz_seed_out_dir();
        fs::create_dir_all(&seed_out_dir).unwrap();

        let crashes_out_dir = self.config.general.sgfuzz_crash_out_dir();
        fs::create_dir_all(&crashes_out_dir).unwrap();

        let workdir = self.config.general.sgfuzz_workdir();
        fs::create_dir_all(&workdir).unwrap();

        let mut log_dir = workdir.clone();
        log_dir.push("logs");
        fs::create_dir_all(&log_dir).unwrap();

        let mut log_path = log_dir.clone();
        log_path.push(format!("{:?}.log", self.id));

        let log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path)
            .unwrap();
        let log_fd = log_file.into_raw_fd();

        let mut cmd = Command::new(&sgfuzz_cfg.bin_path);
        let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
        if self.config.sink.log_stdout || self.config.sink.log_stderr {
            unsafe {
                cmd.stdout(Stdio::from_raw_fd(log_fd));
                cmd.stderr(Stdio::from_raw_fd(log_fd));
            }
        } else {
            unsafe {
                cmd.stdout(Stdio::from_raw_fd(dev_null.as_raw_fd()));
                cmd.stderr(Stdio::from_raw_fd(dev_null.as_raw_fd()));
            }
        }

        cmd.env_clear();
        let env = sgfuzz_cfg.env.clone();
        cmd.envs(env);

        cmd.env("HFND_TCP_PORT", sgfuzz_cfg.dst_port().to_string());

        let asan_options = [
            "abort_on_error=1",
            "symbolize=0",
            "detect_leaks=0",
            "handle_abort=2",
            "handle_segv=2",
            "handle_sigbus=2",
            "handle_sigill=2",
            "detect_stack_use_after_return=0",
            "detect_odr_violation=0",
        ];
        let asan_env_value = asan_options.join(":");
        cmd.env("ASAN_OPTIONS", asan_env_value);

        cmd.args([
            &format!("-artifact_prefix={}/", &crashes_out_dir.to_str().unwrap()).as_str(),
            &"-detect_leaks=0",
            &"-print_final_stats=1",
            &"-reload=30",
            &"-reduce_inputs=1",
            &"-check_input_sha1=1",
            &"-print_full_coverage=1",
            &"-shrink=1",
            &"-close_fd_mask=3",
            &format!("{}/", seed_out_dir.to_str().unwrap()).as_str(),
            &format!("{}/", seed_input_dir.to_str().unwrap()).as_str(),
        ]);

        cmd.arg("--");

        let args = if let Some(ref args) = self.config.sgfuzz.as_ref().unwrap().args {
            args.to_owned()
        } else {
            self.config.sink.arguments().to_owned()
        };
        cmd.args(args);

        let jail_uid_gid = self.config.general.jail_uid_gid();
        if let Some(jail_uid_gid) = jail_uid_gid {
            cmd.uid(jail_uid_gid.0);
            cmd.gid(jail_uid_gid.1);
        }

        dbg!(&cmd.get_args());

        cmd.spawn().expect("Failed to spawn")
    }

    pub fn run(mut self) -> WorkerProxy {
        let (init_finshied_sender, init_finshied_receiver) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            unshare_network_namespace(&self.config);

            let mut restart_ctr = 0;
            let mut child = self.spawn();
            init_finshied_sender.send(()).unwrap();

            loop {
                let id = self.id;
                thread::sleep(Duration::from_secs(5));
                let status = child.try_wait().unwrap();
                if status.is_some() && !self.termination_flag.load(Ordering::SeqCst) {
                    restart_ctr += 1;
                    log::warn!("Worker {id:?} terminated before it was instructed to do so: {status:?}. #restarts: {restart_ctr}");

                    if restart_ctr < RESTART_THRESHOLD {
                        log::warn!("However, since this is libfuzzer, we just expect that it found a bug and going to restart it.");
                    } else {
                        log::error!(
                            "Worker was restarted {RESTART_THRESHOLD} times, this might be a bug."
                        );
                    }

                    thread::sleep(Duration::from_secs(1));
                    child = self.spawn();
                }

                if self.termination_flag.load(Ordering::SeqCst) {
                    log::info!("Termination requested, sending SIGTERM");
                    let child_pid = Pid::from_raw(child.id().try_into().unwrap());
                    let _ = nix::sys::signal::kill(child_pid, SIGTERM);
                    log::info!("Waiting for process {:?} to terminate", child_pid);
                    let ret = child.wait().unwrap();
                    log::info!("Terminated: {ret:?}");
                    return;
                }
            }
        });
        init_finshied_receiver
            .recv_timeout(Duration::from_secs(120))
            .unwrap();

        thread::sleep(Duration::from_secs(10));
        WorkerProxy::new(handle)
    }
}
