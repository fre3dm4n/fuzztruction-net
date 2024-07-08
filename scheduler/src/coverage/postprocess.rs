use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        atomic::{self, AtomicBool, AtomicU32, AtomicUsize},
        Arc, Mutex, RwLock,
    },
};

use super::read_cov_binary_info;
use crate::config::{Config, SinkCovConfig};
use anyhow::{anyhow, Context, Result};
use console::Term;
use glob::glob;
use indicatif::ProgressStyle;
use itertools::Itertools;
use llvm_cov_json::CoverageReport;

use rayon::prelude::*;

use regex::{self, Regex};

use lazy_static::lazy_static;
use serde::Serialize;

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone, Copy, Serialize)]
struct CoveredBranch {
    start_line: u32,
    start_col: u16,
    file_id: u32,
    false_branch: bool,
}

lazy_static! {
    static ref FILE_TO_ID_MAPPING: RwLock<HashMap<&'static str, u32>> = RwLock::new(HashMap::new());
    static ref NEXT_FILE_ID: AtomicU32 = AtomicU32::new(0);
}

fn get_global_file_id(file_path: &str) -> u32 {
    let id = FILE_TO_ID_MAPPING.read().unwrap().get(file_path).copied();
    if let Some(id) = id {
        id
    } else {
        let mut write_lock = FILE_TO_ID_MAPPING.write().unwrap();
        if let Some(id) = write_lock.get(file_path) {
            return *id;
        }
        let file_path = file_path.to_owned().leak();
        let id = NEXT_FILE_ID.fetch_add(1, atomic::Ordering::SeqCst);
        write_lock.insert(file_path, id);
        id
    }
}

fn convert_json_to_covered_branches(json_report: String) -> HashSet<CoveredBranch> {
    let coverage_report = CoverageReport::from_str(&json_report).unwrap();

    let mut branches = HashSet::new();
    for function in coverage_report.data[0].functions.iter() {
        for branch in function.branches.iter() {
            let file_path = function.filenames[branch.file_id as usize];
            let global_file_id = get_global_file_id(file_path);

            let mut covered_branch = CoveredBranch {
                start_line: branch.line_start.try_into().unwrap(),
                start_col: branch.column_start.try_into().unwrap(),
                file_id: global_file_id,
                false_branch: false,
            };

            if branch.execution_count > 0 {
                branches.insert(covered_branch);
            }

            if branch.false_execution_count > 0 {
                covered_branch.false_branch = true;
                branches.insert(covered_branch);
            }
        }
    }
    branches
}

pub fn postprocess_llvm_cov(
    config: &Config,
    termination_flag: Arc<AtomicBool>,
    job_cnt: usize,
) -> Result<()> {
    let llvm_cov_path = config.general.llvm_cov_directory();
    if !llvm_cov_path.exists() {
        return Err(anyhow!(
            "{} does not exists, unable to perform postprocessing",
            llvm_cov_path.display()
        ));
    }

    let cov_config = read_cov_binary_info(config, &llvm_cov_path);

    let bin_path = cov_config.bin_path.to_str().unwrap();

    create_pool(job_cnt).unwrap().install(|| {
        compute_coverage_over_time(&llvm_cov_path, termination_flag, &cov_config);
        compute_coverage_report(llvm_cov_path, bin_path.to_owned()).unwrap();
    });

    Ok(())
}

fn compute_coverage_report(
    llvm_cov_path: PathBuf,
    cov_binary_path: String,
) -> Result<(), anyhow::Error> {
    let profdata_merged_path =
        merge_prodata_files(&llvm_cov_path, &cov_binary_path).context("Merging profraw files")?;
    generate_html_report(&llvm_cov_path, &profdata_merged_path, &cov_binary_path)
        .context("generating html report")?;
    generate_summary(&llvm_cov_path, &profdata_merged_path, &cov_binary_path)
        .context("generating summary")?;
    Ok(())
}

fn merge_prodata_files(
    llvm_cov_path: &Path,
    _cov_binary_path: &str,
) -> Result<PathBuf, anyhow::Error> {
    let profraw_paths = get_profdata_paths(llvm_cov_path);
    let profraw_paths = profraw_paths
        .into_iter()
        .map(|p| p.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let profraw_paths_len = profraw_paths.len();
    log::info!("Merging {profraw_paths_len} prowraw files");

    let mut profraw_paths_list = tempfile::NamedTempFile::new()?;
    let profraw_paths = profraw_paths.join("\n");
    profraw_paths_list.write_all(profraw_paths.as_bytes())?;
    profraw_paths_list.flush()?;

    let profraw_paths_list_path = profraw_paths_list.path().to_str().unwrap();
    let mut profdata_merged_path = llvm_cov_path.to_owned();
    profdata_merged_path.push("merged.profdata");
    let mut cmd = Command::new("llvm-profdata");
    cmd.args([
        "merge",
        "-f",
        profraw_paths_list_path,
        "-o",
        profdata_merged_path.to_str().unwrap(),
    ]);
    let child = cmd.spawn()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("Failed to merge report: {:#?}", output));
    }
    Ok(profdata_merged_path)
}

fn generate_html_report(
    llvm_cov_path: &Path,
    profdata_merged_path: &Path,
    cov_binary_path: &str,
) -> Result<(), anyhow::Error> {
    let mut cov_html_report_dir = llvm_cov_path.to_owned();
    cov_html_report_dir.push("results/html-report");
    fs::create_dir_all(cov_html_report_dir.parent().unwrap()).unwrap();

    let mut cmd = Command::new("llvm-cov");
    cmd.args([
        "show",
        "--format=html",
        "--instr-profile",
        profdata_merged_path.to_str().unwrap(),
        "-o",
        cov_html_report_dir.to_str().unwrap(),
        &cov_binary_path,
    ]);
    let child = cmd.spawn()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to export report for {}: {:#?}",
            profdata_merged_path.display(),
            output
        ));
    };
    Ok(())
}

fn generate_summary(
    llvm_cov_path: &Path,
    profdata_merged_path: &Path,
    cov_binary_path: &str,
) -> Result<(), anyhow::Error> {
    let mut summary_out_path = llvm_cov_path.to_owned();
    summary_out_path.push("results/summary.txt");
    fs::create_dir_all(summary_out_path.parent().unwrap()).unwrap();

    let mut cmd = Command::new("llvm-cov");
    cmd.stdout(Stdio::piped());
    cmd.args([
        "report",
        "--instr-profile",
        profdata_merged_path.to_str().unwrap(),
        &cov_binary_path,
    ]);
    let child = cmd.spawn()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to export report for {}: {:#?}",
            profdata_merged_path.display(),
            output
        ));
    };

    fs::write(summary_out_path, &output.stdout)?;

    Ok(())
}

pub fn create_pool(num_threads: usize) -> Result<rayon::ThreadPool> {
    match rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
    {
        Err(e) => Err(e.into()),
        Ok(pool) => Ok(pool),
    }
}

fn compute_coverage_over_time(
    llvm_cov_path: &Path,
    termination_flag: Arc<AtomicBool>,
    cfg: &SinkCovConfig,
) {
    let term = Term::stdout();
    let is_not_a_terminal = !term.is_term();

    let mut cov_cnt_over_time_report = llvm_cov_path.to_owned();
    cov_cnt_over_time_report.push("results/coverage.json");
    fs::create_dir_all(cov_cnt_over_time_report.parent().unwrap()).unwrap();

    let mut cov_over_time_report = llvm_cov_path.to_owned();
    cov_over_time_report.push("results/line-coverage.json");

    let mut id_to_file_path_report = llvm_cov_path.to_owned();
    id_to_file_path_report.push("results/id-to-file-path.json");

    let ts_to_covered_branches: Mutex<HashMap<u64, HashSet<CoveredBranch>>> =
        Mutex::new(HashMap::new());
    let ts_regex = Regex::new(r"ts:([0-9]+)").unwrap();

    let mut profraw_and_profdata = get_profraw_paths(llvm_cov_path);
    profraw_and_profdata.extend(get_profdata_paths(llvm_cov_path));

    let reports_done = AtomicUsize::new(0);
    let reports_len = profraw_and_profdata.len();
    log::info!("Processing {} files", reports_len);

    let progress_bar = indicatif::ProgressBar::new(reports_len as u64)
        .with_finish(indicatif::ProgressFinish::Abandon);
    progress_bar.set_style(
        ProgressStyle::with_template("{eta_precise}{bar:60.cyan/blue}{pos:>7}/{len:7}").unwrap(),
    );
    progress_bar.tick();

    profraw_and_profdata
        .par_iter()
        .for_each(|profraw_or_profdata_file| {
            if termination_flag.load(atomic::Ordering::SeqCst) {
                return;
            }

            if is_not_a_terminal {
                let progress = reports_done.fetch_add(1, atomic::Ordering::SeqCst);
                if progress > 0 && progress % 10 == 0 {
                    log::info!("{progress} of {reports_len} done");
                }
            }

            let ts: u64 = ts_regex
                .captures(
                    profraw_or_profdata_file
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                )
                .unwrap()
                .get(1)
                .unwrap()
                .as_str()
                .parse()
                .unwrap();

            let profdata_path = convert_profraw_into_profdata_and_delete(profraw_or_profdata_file);
            let profdata_path = match &profdata_path {
                Ok(profdata_path) => profdata_path,
                Err(err) => {
                    log::error!(
                        "Failed to process {}, skipping: {:#?}",
                        profraw_or_profdata_file.display(),
                        err
                    );
                    progress_bar.inc(1);
                    return;
                }
            };

            let ret = convert_profdata_to_json(profdata_path, cfg);
            match ret {
                Err(err) => {
                    log::error!(
                        "Failed to covert {} to json: {:#?}",
                        profdata_path.display(),
                        err
                    );
                }
                Ok(json_report) => {
                    let branches = convert_json_to_covered_branches(json_report);
                    ts_to_covered_branches
                        .lock()
                        .unwrap()
                        .entry(ts)
                        .and_modify(|b| b.extend(branches.clone()))
                        .or_insert(branches);
                }
            }

            progress_bar.inc(1);
        });

    if termination_flag.load(atomic::Ordering::SeqCst) {
        return;
    }

    let ts_to_covered_branches = ts_to_covered_branches.into_inner().unwrap();
    if ts_to_covered_branches.is_empty() {
        panic!("This is odd, no covered branches have been recorded");
    }

    let max_ts = *ts_to_covered_branches.keys().max().unwrap();

    let mut seen_branches = HashSet::new();
    let mut ts_to_covered_branches_cnt: HashMap<u64, u64> = HashMap::new();

    for ts in 0..=max_ts {
        if let Some(branches) = ts_to_covered_branches.get(&ts) {
            let old_seen_branches_cnt = seen_branches.len();
            seen_branches.extend(branches.clone());
            if old_seen_branches_cnt != seen_branches.len() {
                ts_to_covered_branches_cnt.insert(ts, seen_branches.len() as u64);
            }
        }
    }

    //let mut id_to_filename_mapping = HashMap::<usize, &str>::new();
    let id_to_filename_mapping = FILE_TO_ID_MAPPING
        .read()
        .unwrap()
        .iter()
        .map(|e| (*e.1, e.0.to_owned()))
        .collect::<HashMap<_, _>>();

    let report = serde_json::to_string(&id_to_filename_mapping).unwrap();
    fs::write(id_to_file_path_report, report).unwrap();

    let report = serde_json::to_string(&ts_to_covered_branches).unwrap();
    fs::write(cov_over_time_report, report).unwrap();

    let report = serde_json::to_string(&ts_to_covered_branches_cnt).unwrap();
    fs::write(cov_cnt_over_time_report, report).unwrap();
}

fn get_profraw_paths(llvm_cov_path: &Path) -> Vec<PathBuf> {
    let llvm_reports = glob(&format!("{}/**/*.profraw", llvm_cov_path.to_str().unwrap())).unwrap();
    llvm_reports.into_iter().flatten().collect_vec()
}

fn get_profdata_paths(llvm_cov_path: &Path) -> Vec<PathBuf> {
    let llvm_reports = glob(&format!(
        "{}/**/*.profdata",
        llvm_cov_path.to_str().unwrap()
    ))
    .unwrap();
    llvm_reports
        .into_iter()
        .flatten()
        .filter(|f| f.file_name().unwrap().to_str().unwrap() != "merged.profdata")
        .collect_vec()
}

fn convert_profdata_to_json(profdata_path: &Path, cfg: &SinkCovConfig) -> Result<String> {
    let mut dst_path = profdata_path.to_owned();
    dst_path.set_extension("json");
    let mut cmd = Command::new("llvm-cov");
    cmd.envs(cfg.env.clone());
    cmd.stdout(Stdio::piped());
    cmd.args([
        "export",
        "--format=text",
        "--num-threads=8",
        "-skip-expansions",
        "--instr-profile",
        profdata_path.to_str().unwrap(),
        cfg.bin_path.to_str().unwrap(),
    ]);
    let child = cmd.spawn()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        Err(anyhow!(
            "Failed to export report for {}: {:#?}",
            profdata_path.display(),
            output
        ))
    } else {
        Ok(String::from_utf8(output.stdout)?)
    }
}

fn convert_profraw_into_profdata_and_delete(profraw_file: &Path) -> Result<PathBuf> {
    let mut dst_path = profraw_file.to_owned();
    dst_path.set_extension("profdata");
    if profraw_file.extension() == Some(&OsString::from_str("profdata").unwrap()) {
        return Ok(profraw_file.to_owned());
    }

    let mut cmd = Command::new("llvm-profdata");
    cmd.args([
        "merge",
        "--num-threads=8",
        "-sparse",
        "-o",
        dst_path.to_str().unwrap(),
        profraw_file.to_str().unwrap(),
    ]);
    let child = cmd.spawn()?;
    let result = child.wait_with_output()?;
    if !result.status.success() {
        return Err(anyhow!(format!(
            "Failed to execute llvm-profdata: {:#?}",
            result
        )));
    }

    let _ = fs::remove_file(profraw_file);
    Ok(dst_path)
}
