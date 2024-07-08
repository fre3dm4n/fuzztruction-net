use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use super::aflnet::compute_llvm_cov_afl_like_inputs;
use crate::config::Config;
use anyhow::Result;
use glob::glob;
use itertools::Itertools;

pub fn compute_llvm_cov(
    config: &Config,
    exit_requested: Arc<AtomicBool>,
    jobs: usize,
    timeout: Duration,
    overwrite_results: bool,
) -> Result<()> {
    let inputs_glob = format!(
        "{}/**/replayable-queue",
        config.general.stateafl_workdir().to_str().unwrap()
    );
    let input_dirs = glob(&inputs_glob).unwrap();
    let input_dirs: Vec<std::path::PathBuf> = input_dirs.into_iter().flatten().collect_vec();
    let input_dirs_ref = input_dirs.iter().map(|p| p.as_path()).collect::<Vec<_>>();

    compute_llvm_cov_afl_like_inputs(
        config,
        exit_requested,
        jobs,
        timeout,
        overwrite_results,
        input_dirs_ref,
        true,
    )
}
