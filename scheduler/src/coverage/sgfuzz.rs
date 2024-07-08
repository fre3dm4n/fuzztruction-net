use std::{
    collections::HashMap,
    fs,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use crate::config::Config;

use super::aflnet::compute_llvm_cov_afl_like_inputs;
use anyhow::Result;
use itertools::Itertools;

pub fn compute_llvm_cov(
    config: &Config,
    exit_requested: Arc<AtomicBool>,
    jobs: usize,
    timeout: Duration,
    overwrite_results: bool,
) -> Result<()> {
    let seeds_with_ts_dir = config.general.sgfuzz_seed_with_ts_out_dir();
    fs::create_dir_all(&seeds_with_ts_dir).unwrap();

    let findings_dir = config.general.sgfuzz_seed_out_dir();
    let findings = glob::glob(&format!("{}/*", findings_dir.to_str().unwrap()))
        .unwrap()
        .flatten()
        .collect::<Vec<_>>();
    let seeds = glob::glob(&format!(
        "{}/*",
        config.sgfuzz.as_ref().unwrap().input_dir.to_str().unwrap()
    ))
    .unwrap()
    .flatten();

    let mut findigs_to_modified_ts = HashMap::new();
    for finding in findings {
        let stats = fs::metadata(&finding).unwrap();
        let modified = stats.modified().unwrap();
        findigs_to_modified_ts.insert(finding, modified);
    }

    let min_modified_ts = *findigs_to_modified_ts.values().min().unwrap();

    // Seeds have all the lowest ts.
    for seed in seeds {
        findigs_to_modified_ts.insert(seed, min_modified_ts);
    }

    for (idx, (finding, creation_ts)) in findigs_to_modified_ts
        .into_iter()
        .sorted_by_key(|e| e.1)
        .enumerate()
    {
        let offset_to_start = creation_ts.duration_since(min_modified_ts).unwrap();
        let dst_name = format!(
            "id:{},ts:{},{}",
            idx,
            offset_to_start.as_millis(),
            finding.file_name().unwrap().to_str().unwrap()
        );
        let mut dst_path = seeds_with_ts_dir.clone();
        dst_path.push(dst_name);
        fs::copy(finding, dst_path).unwrap();
    }

    compute_llvm_cov_afl_like_inputs(
        config,
        exit_requested,
        jobs,
        timeout,
        overwrite_results,
        vec![&config.general.sgfuzz_seed_with_ts_out_dir()],
        false,
    )
}
