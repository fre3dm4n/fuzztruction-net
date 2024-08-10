use std::{
    fs::{self, read_to_string},
    process::Command,
};

use anyhow::{anyhow, Context, Result};
use jail::jail::wrap_libc;
use nix::{
    sys::{
        resource::{getrlimit, setrlimit, Resource},
        stat::{umask, Mode},
    },
    unistd::Uid,
};

use crate::{config::Config, error::CliError, fuzzer::queue::Input};

fn check_perf_event_paranoid() -> Result<()> {
    let content = read_to_string("/proc/sys/kernel/perf_event_paranoid");
    let content = content.expect("Failed to open /proc/sys/kernel/perf_event_paranoid");
    let level = content.trim().parse::<i32>().unwrap();
    if level > 1 {
        return Err(anyhow!(
            "Please run\necho 1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
        ));
    }
    Ok(())
}

/// Check whether core_pattern is not set to 'core'. If this is the case, we need
/// to pay the overhead of creating a core image each time we crash during an execution.
fn check_core_pattern_is_core() -> Result<()> {
    let content = read_to_string("/proc/sys/kernel/core_pattern");
    let content = content.expect("Failed to open /proc/sys/kernel/core_pattern.");
    if content.trim() != "core" {
        return Err(anyhow!("Please run\necho core | sudo tee /proc/sys/kernel/core_pattern\nto disabling core dumping on segmentationfaults."));
    }
    Ok(())
}

fn check_fs_suid_dumpable() -> Result<()> {
    let content = read_to_string("/proc/sys/fs/suid_dumpable");
    let content = content.expect("Failed to open /proc/sys/fs/suid_dumpable.");
    if content.trim() != "0" {
        return Err(anyhow!(
            "Please run\necho 0 | sudo tee /proc/sys/fs/suid_dumpable\nto allow the core_pattern 'core'."
        ));
    }
    Ok(())
}

/// Check if the /tmp directory is mounted using tmpfs as filesystem.
/// Since we are reading and writing to this directory with a hight frequency, this
/// gives us a performance boost.
fn check_if_tmp_is_tmpfs() -> Result<()> {
    let content = read_to_string("/proc/mounts");
    let content = content.expect("Failed to open /proc/mounts.");

    let lines = content.split('\n');
    let lines = lines
        .into_iter()
        .filter(|e| e.contains("tmpfs /tmp "))
        .collect::<Vec<_>>();

    if lines.len() > 1 {
        return Err(anyhow!(
            "Found multiple mounts for /tmp:\n{lines:#?}",
            lines = lines
        ));
    } else if lines.is_empty() {
        return Err(anyhow!("Could not find a mount for /tmp."));
    }

    if !lines[0].contains("tmpfs") {
        return Err(anyhow!(
            "Please mount /tmp with tmpfs as filesystem:\nsudo mount -t tmpfs none /tmp"
        ));
    }

    Ok(())
}

/// Check if binaries dynamically linked against the source agent are able to find
/// the source agent shared object during linktime.
fn check_if_agent_is_in_path() -> Result<()> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("ldconfig -p | grep libgenerator_agent.so")
        .output()
        .expect("Failed to run command.");

    if !output.status.success() {
        let mut msg =
            "Failed to find libgenerator_agent.so in ld's path. Please run the following commands:\n"
                .to_owned();
        msg.push_str("echo '/home/user/leah/target/debug' > /etc/ld.so.conf.d/fuzztruction.conf\n");
        msg.push_str("sudo ldconfig");
        Err(CliError::ConfigurationError(format!("{:#?}", output))).context(msg)?;
    }

    Ok(())
}

fn check_scaling_governor() -> Result<()> {
    let governor = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
    if let Ok(governor) = governor {
        if governor.trim() != "performance" {
            return Err(anyhow!("Please run echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"));
        }
    } else {
        log::warn!(
            "Failed to set governor. Probably this is not supported by this system: {governor:#?}"
        );
    }

    Ok(())
}

fn check_file_limit() -> Result<()> {
    let (soft_limit, hard_limit) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    if soft_limit < hard_limit {
        log::info!("Increasing RLIMIT_NOFILE to {hard_limit}");
        setrlimit(Resource::RLIMIT_NOFILE, hard_limit, hard_limit).unwrap();
    }

    Ok(())
}

fn check_mqueue_queues_max() -> Result<()> {
    let procfs_file = "/proc/sys/fs/mqueue/queues_max";
    let limit: u64 = fs::read_to_string(procfs_file)
        .context(format!("Failed to read {procfs_file}"))?
        .trim()
        .parse()
        .unwrap();
    if limit < 1024 {
        fs::write(procfs_file, "1024").unwrap();
    }
    Ok(())
}

/// Check if all requirements to run this software are satisfied.
pub fn check_system() -> Result<()> {
    check_core_pattern_is_core()?;
    check_fs_suid_dumpable()?;
    check_if_tmp_is_tmpfs()?;
    check_if_agent_is_in_path()?;
    check_scaling_governor()?;
    check_perf_event_paranoid()?;
    check_file_limit()?;
    check_mqueue_queues_max()?;
    Ok(())
}

fn check_jail(config: &Config) -> Result<()> {
    if let Some((uid, _gid)) = config.general.jail_uid_gid() {
        log::info!("Checking whether we have enough permissions to jail the fuzzing process.");
        unsafe {
            let ret = wrap_libc(|| libc::seteuid(0));
            if let Err(err) = ret {
                return Err(anyhow!("Failed to set EUID to 0. If jailing is enable, this process must be run as root: {:#?}", err));
            }
            let ret = wrap_libc(|| libc::seteuid(uid));
            if let Err(err) = ret {
                return Err(anyhow!(
                    "Failed to set EUID to {}. Is the jail-uid valid?: {:#?}",
                    uid,
                    err
                ));
            }
        }
    }
    if let Err(err) = nix::unistd::setuid(Uid::from_raw(0)) {
        return Err(anyhow!("Failed to set UID to 0: {err:#?}"));
    }

    log::info!("Changeing umask to 0o000");
    umask(Mode::empty());

    Ok(())
}

fn check_input_directory(config: &Config) -> Result<()> {
    let input_dir = &config.general.input_dir;
    let inputs = Input::from_dir(input_dir).context("Failed to access inputs directory")?;
    if inputs.is_empty() {
        return Err(anyhow!(
            "No inputs found in input directory {:?}",
            input_dir
        ));
    }
    Ok(())
}

pub fn check_config(config: &Config) -> Result<()> {
    check_jail(config)?;
    check_input_directory(config)?;
    Ok(())
}
