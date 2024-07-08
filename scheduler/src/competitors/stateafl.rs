use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
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

use crate::config::Config;
use anyhow::Result;
use itertools::Itertools;
use wait_timeout::ChildExt;

use super::worker::{unshare_network_namespace, WorkerId, WorkerProxy};

use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};

#[derive(Debug)]
pub(super) struct StateAflWorker {
    id: WorkerId,
    config: Config,
    termination_flag: Arc<AtomicBool>,
}

impl StateAflWorker {
    pub fn new(id: WorkerId, config: &Config, termination_flag: Arc<AtomicBool>) -> Self {
        StateAflWorker {
            id,
            config: config.clone(),
            termination_flag,
        }
    }

    fn prepare_env(&self) -> Vec<(String, String)> {
        let cfg = self.config.stateafl.as_ref().unwrap();
        cfg.env.clone()
    }

    fn _loop(self, init_finished: mpsc::Sender<()>) {
        let stateafl_config = self
            .config
            .stateafl
            .as_ref()
            .expect("Target has no StateAfl config");

        let seed_dir = stateafl_config.input_dir.clone();
        let workdir = self.config.general.stateafl_workdir();
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

        let mut cmd = Command::new("/competitors/stateafl/afl-fuzz");

        unsafe {
            cmd.stdout(Stdio::from_raw_fd(log_fd));
            cmd.stderr(Stdio::from_raw_fd(log_fd));
        }

        // Do not render the AFL UI
        cmd.env_clear();
        cmd.env("AFL_NO_UI", "1");

        if env::var("FT_NO_AFFINITY").is_ok() {
            cmd.env("AFL_NO_AFFINITY", "1");
        }

        cmd.args(["-m", "none"]);

        // set environment from config
        let env = self.prepare_env();
        cmd.envs(env);

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
        cmd.args(["-N", &stateafl_config.netinfo]);

        // -q algo: (optional) state selection algorithm (e.g., 1. RANDOM_SELECTION, 2. ROUND_ROBIN, 3. FAVOR)
        cmd.args(["-q", "3"]);

        // -s algo: (optional) seed selection algorithm (e.g., 1. RANDOM_SELECTION, 2. ROUND_ROBIN, 3. FAVOR)
        cmd.args(["-s", "3"]);

        //-R : (optional) enable region-level mutation operators
        cmd.args(["-R"]);

        if stateafl_config.enable_state_aware_mode {
            // enable state aware mode
            cmd.args(["-E"]);
        }

        if stateafl_config.send_sigterm {
            cmd.args(["-K"]);
        }

        // protocol used by the server, e.g., RTSP, FTP, DTLS12, DNS, DICOM, SMTP, SSH, TLS, DAAP-HTTP, SIP
        // assert!([
        //     "RTSP",
        //     "FTP",
        //     "DTLS12",
        //     "DNS",
        //     "DICOM",
        //     "SMTP",
        //     "SSH",
        //     "TLS",
        //     "DAAP-HTTP",
        //     "SIP"
        // ]
        // .contains(&stateafl_config.protocol.as_str()));
        // cmd.args(["-P", &stateafl_config.protocol]);

        cmd.env("AFL_NO_AFFINITY", "1");

        cmd.arg("--");

        let mut args = vec![stateafl_config
            .bin_path
            .clone()
            .to_str()
            .unwrap()
            .to_owned()];
        args.extend(self.config.sink.arguments);
        cmd.args(args);

        let args = cmd.get_args().collect_vec();
        let args = args
            .into_iter()
            .map(|arg| arg.to_str().unwrap())
            .collect_vec();

        log::info!("cmd:\n/competitors/stateafl/afl-fuzz {}", args.join(" "));

        let env = cmd.get_envs().collect_vec();
        let env = env
            .into_iter()
            .map(|env| {
                (
                    env.0.to_str().unwrap(),
                    env.1.map(|v| v.to_str().unwrap()).unwrap_or(""),
                )
            })
            .collect_vec();
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

        OpenOptions::new()
            .write(true)
            .open("/proc/sys/kernel/randomize_va_space")
            .unwrap()
            .write_all("0".as_bytes())
            .unwrap();

        let mut child = None;
        for try_idx in 0..6 {
            log::info!(
                "Try {try_idx}. Waiting for 5 seconds to see whether the worker crashed on import."
            );
            child = Some(cmd.spawn().expect("Failed to spawn"));
            if let Ok(None) = child.as_mut().unwrap().wait_timeout(Duration::from_secs(5)) {
                log::info!("Success!");
                break;
            }
        }
        init_finished.send(()).unwrap();
        let mut child = child.expect("Failed to spawn worker");

        loop {
            let id = self.id;
            thread::sleep(Duration::from_secs(5));
            let status = child.try_wait().unwrap();
            if status.is_some() && !self.termination_flag.load(Ordering::SeqCst) {
                log::error!(
                    "Worker {id:?} terminated before it was instructed to do so: {status:?}"
                );
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
            self._loop(init_finshied_sender)
        });
        init_finshied_receiver
            .recv_timeout(Duration::from_secs(120))
            .unwrap();
        WorkerProxy::new(handle)
    }
}
