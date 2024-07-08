use std::{
    fs::{self, OpenOptions},
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

use crate::config::{self, Config};
use anyhow::Result;
use itertools::Itertools;

use super::worker::{unshare_network_namespace, WorkerId, WorkerProxy};

use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};

#[derive(Debug)]
pub struct AflNetWorker {
    id: WorkerId,
    config: Config,
    termination_flag: Arc<AtomicBool>,
}

impl AflNetWorker {
    pub fn new(id: WorkerId, config: &Config, termination_flag: Arc<AtomicBool>) -> Self {
        AflNetWorker {
            id,
            config: config.clone(),
            termination_flag,
        }
    }

    fn prepare_env(&self) -> Vec<(String, String)> {
        let cfg = self.config.aflnet.as_ref().unwrap();
        cfg.env.clone()
    }

    fn _loop(self, init_finished: mpsc::Sender<()>) {
        let aflnet_config = self.config.aflnet.as_ref().unwrap();

        let seed_dir = aflnet_config.input_dir.clone();
        let workdir = self.config.general.aflnet_workdir();
        fs::create_dir_all(&workdir).unwrap();

        let mut log_path = workdir.clone();
        log_path.push("logs");
        fs::create_dir_all(&log_path).unwrap();

        log_path.push(format!("{:?}.log", self.id));

        let log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path)
            .unwrap();
        let log_fd = log_file.into_raw_fd();

        let mut cmd = Command::new("/competitors/aflnet/afl-fuzz");

        unsafe {
            cmd.stdout(Stdio::from_raw_fd(log_fd));
            cmd.stderr(Stdio::from_raw_fd(log_fd));
        }

        // Do not render the AFL UI
        cmd.env_clear();
        cmd.env("AFL_NO_UI", "1");
        cmd.env("AFL_SKIP_CRASHES", "1");

        // if env::var("FT_NO_AFFINITY").is_ok() {
        // }
        cmd.env("AFL_NO_AFFINITY", "1");

        cmd.args(["-m", "none"]);

        // set environment from config
        let env = self.prepare_env();
        cmd.envs(env);

        // input and output directory
        cmd.args([
            "-i",
            seed_dir.to_str().unwrap(),
            "-o",
            workdir.to_str().unwrap(),
        ]);

        // determine whether this is a master or slave worker
        let id = match self.id {
            WorkerId::Master => "-Mmaster".to_owned(),
            WorkerId::Slave(slave_id) => format!("-Sslave{}", slave_id),
        };
        cmd.arg(id);

        // network address of the server, e.g., tcp://127.0.0.1/8554
        cmd.args(["-N", &aflnet_config.netinfo]);

        // protocol used by the server, e.g., RTSP, FTP, DTLS12, DNS, DICOM, SMTP, SSH, TLS, DAAP-HTTP, SIP
        assert!([
            "RTSP",
            "FTP",
            "DTLS12",
            "DNS",
            "DICOM",
            "SMTP",
            "SSH",
            "TLS",
            "DAAP-HTTP",
            "SIP",
            "NOP",
        ]
        .contains(&aflnet_config.protocol.as_str()));
        cmd.args(["-P", &aflnet_config.protocol]);

        if self.config.aflnet.as_ref().unwrap().enable_state_aware_mode {
            // enable state aware mode
            cmd.args(["-E"]);
        }

        // enable region-level mutation operators
        cmd.args(["-R"]);

        if aflnet_config.send_sigterm {
            cmd.arg("-K");
        }

        cmd.args(["-t", "500+"]);

        cmd.arg("--");

        let mut args = vec![aflnet_config.bin_path.clone().to_str().unwrap().to_owned()];
        args.extend(self.config.sink.arguments);
        cmd.args(args);

        let args = cmd.get_args().collect_vec();
        let args = args
            .into_iter()
            .map(|arg| arg.to_str().unwrap())
            .collect_vec();

        log::info!("cmd:\n/competitors/aflnet/afl-fuzz {}", args.join(" "));

        let env = cmd.get_envs().collect_vec();
        let mut env = env
            .into_iter()
            .map(|env| {
                (
                    env.0.to_str().unwrap(),
                    env.1.map(|v| v.to_str().unwrap()).unwrap_or(""),
                )
            })
            .collect_vec();

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

        env.push(("ASAN_OPTIONS", &asan_env_value));

        let mut export_cmd = String::new();
        for (k, v) in env {
            export_cmd.push_str("export ");
            export_cmd.push_str(k);
            if !v.is_empty() {
                export_cmd.push_str(&format!("=\"{}\"", v));
            }
            export_cmd.push('\n');
        }
        log::info!("env:\n{}", export_cmd);

        // Make sure that UID == EUID, since if this is not the case,
        // ld will ignore LD_PRELOAD which we need to use for targets
        // that normally load instrumented libraries during runtime.
        // assert_eq!(nix::unistd::getuid(), nix::unistd::geteuid());
        // assert_eq!(nix::unistd::getegid(), nix::unistd::getegid());

        let jail_uid_gid = self.config.general.jail_uid_gid();
        if let Some(jail_uid_gid) = jail_uid_gid {
            cmd.uid(jail_uid_gid.0);
            cmd.gid(jail_uid_gid.1);
        }

        let mut child = cmd.spawn().unwrap();
        init_finished.send(()).unwrap();

        loop {
            thread::sleep(Duration::from_secs(5));
            let status = child.try_wait().unwrap();
            if status.is_some() && !self.termination_flag.load(Ordering::SeqCst) {
                log::error!("Worker terminated before it was instructed to do so: {status:?}");
                return;
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
    }

    #[allow(unused)]
    fn drop_privileges(&mut self) -> Result<()> {
        todo!();
    }

    pub fn run(self) -> WorkerProxy {
        let (init_finshied_sender, init_finshied_receiver) = mpsc::channel::<()>();
        let handle = thread::spawn(|| {
            unshare_network_namespace(&self.config);
            // if let Err(err) = self.drop_privileges() {
            //     log::error!("Failed to drop privileges: {:#?}", err);
            //     panic!();
            // }
            self._loop(init_finshied_sender)
        });
        init_finshied_receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        WorkerProxy::new(handle)
    }
}
