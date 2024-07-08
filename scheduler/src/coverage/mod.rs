use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::config::{Config, SinkCovConfig};

pub mod aflnet;
pub mod classic;
pub mod networked;
pub mod sgfuzz;
pub mod stateafl;

mod postprocess;
pub use postprocess::postprocess_llvm_cov;

fn info_path(llvm_traces_folder: &Path) -> PathBuf {
    let mut cov_binary_info_path = llvm_traces_folder.to_owned();
    cov_binary_info_path.push("cov_binary_info.json");
    cov_binary_info_path
}

fn write_cov_binary_info(config: &Config, llvm_traces_folder: &Path) {
    let cov_binary_info_path = info_path(llvm_traces_folder);

    let mut cov_bin_info = config
        .sink_cov
        .as_ref()
        .expect("sink-cov section missing in config")
        .clone();

    let fname = cov_bin_info.bin_path.file_name().unwrap();
    let mut cov_bin_copy_dst = llvm_traces_folder.to_owned();
    cov_bin_copy_dst.push(fname);
    fs::copy(&cov_bin_info.bin_path, &cov_bin_copy_dst).expect("Does the coverage binary exists?");

    cov_bin_info.bin_path = cov_bin_copy_dst;

    let json = serde_json::to_string_pretty(&cov_bin_info).unwrap();
    fs::write(cov_binary_info_path, json).unwrap();
}

fn read_cov_binary_info(_config: &Config, llvm_traces_folder: &Path) -> SinkCovConfig {
    let cov_binary_info_path = info_path(llvm_traces_folder);
    let content = fs::read_to_string(cov_binary_info_path).unwrap();
    let mut config: SinkCovConfig = serde_json::from_str(&content).unwrap();

    let bin_name = config.bin_path.file_name().unwrap().to_str().unwrap();
    let mut bin_copy_path = llvm_traces_folder.to_owned();
    bin_copy_path.push(bin_name);
    config.bin_path = bin_copy_path;

    config
}
