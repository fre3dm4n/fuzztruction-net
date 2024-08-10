use std::{path::PathBuf, str::FromStr, sync::Mutex, time::Duration};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use scheduler::{
    io_channels::{InputChannel, OutputChannel},
    logging::setup_logger,
    mutation_cache::MutationCache,
    mutation_cache_ops::MutationCacheOpsEx,
    source::{RunResult, Source},
};

fn tests_path() -> PathBuf {
    let mut path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR")).unwrap();
    path.push("tests");
    path
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(clippy::read_zero_byte_vec)]
fn test_instrumentation(workdir: PathBuf, total_size: usize, access_size_bits: usize) {
    let tests_path = tests_path();
    let mut bin_path = tests_path.clone();
    bin_path.push("target_1/generator");

    let access_total_size = total_size;

    let mut source = Source::new(
        bin_path,
        vec![access_total_size.to_string()],
        workdir,
        InputChannel::None,
        OutputChannel::Stdout,
        true,
        false,
        true,
        None,
    )
    .unwrap();

    source.start().unwrap();
    let mut patch_points = Vec::clone(&source.get_patchpoints().unwrap());
    assert_eq!(patch_points.len(), 1);
    assert!(access_size_bits <= 8);

    unsafe {
        patch_points
            .get_mut(0)
            .unwrap()
            .set_target_value_size_in_bits(access_size_bits as u32);
    }

    let target_patch_point = patch_points.get(0).unwrap().clone();

    let mc = MutationCache::from_patchpoints(patch_points.iter()).unwrap();
    unsafe {
        source.mutation_cache_replace(&mc).unwrap();
    }

    let (res, trace) = source.trace(DEFAULT_TIMEOUT).unwrap();
    assert!(matches!(res, RunResult::Terminated { exit_code: 0, .. }));
    assert_eq!(trace.len(), 1);

    let hits = trace.hits_mapping();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        *hits.get(&target_patch_point.id()).unwrap(),
        access_total_size as u64
    );

    // enable the patch point
    let mc = source.mutation_cache();
    unsafe {
        mc.borrow_mut().resize_covered_entries(&trace);
    }
    source.sync_mutations().unwrap();

    let mc_entries = mc.borrow_mut().entries_mut_ptr();
    assert_eq!(mc_entries.len(), 1);

    let target_mce = unsafe { &mut *(*mc_entries.first().unwrap()) };
    assert_eq!(target_mce.msk_len(), total_size as u32);

    let mut rng = StdRng::seed_from_u64(1);

    for _ in 0..250 {
        let mut msk = vec![0u8; access_total_size];
        rng.fill_bytes(&mut msk);
        target_mce.get_msk_as_slice().copy_from_slice(&msk);
        eprintln!("msk: {:?}", msk);

        source.spawn(DEFAULT_TIMEOUT).unwrap();
        source
            .wait_for_child_termination(DEFAULT_TIMEOUT, false)
            .unwrap();
        let mut output = Vec::<u8>::new();
        source.read(&mut output);

        let output = String::from_utf8(output).unwrap();
        let lines = output
            .lines()
            .map(|line| u8::from_str_radix(line, 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), access_total_size);

        let mut bit_idx = 0usize;

        for line in lines.into_iter().enumerate() {
            eprintln!("line: {:?}", line);
            let start_byte_idx = bit_idx / 8;
            let end_byte_idx = (bit_idx + access_size_bits - 1) / 8;
            if start_byte_idx != end_byte_idx {
                let val_msk = (1 << access_size_bits) - 1;
                assert!(start_byte_idx + 1 == end_byte_idx);
                let val: u16 = msk[start_byte_idx] as u16 | (msk[end_byte_idx] as u16) << 8u16;
                let val = (val & (val_msk << (bit_idx % 8))) >> (bit_idx % 8);
                assert_eq!(line.1, val as u8);
            } else {
                let val_msk = ((1u16 << access_size_bits) - 1) as u8;
                let val = (msk[start_byte_idx] & (val_msk << (bit_idx % 8))) >> (bit_idx % 8);
                assert_eq!(line.1, val);
            }
            bit_idx += access_size_bits;
        }
    }
}

static LOGGING_SETUP_DONE: Mutex<bool> = Mutex::new(false);

fn setup_logging(log_path: PathBuf) {
    let mut lock = LOGGING_SETUP_DONE.lock().unwrap();
    if !*lock {
        *lock = true;
        setup_logger(&log_path, "trace").unwrap();
    }
}

#[test]
fn test_instrumentation_bytes_all() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let workdir = tmp_dir.into_path();
    eprintln!("workdir: {:?}", &workdir);

    let mut log_path = workdir.clone();
    log_path.push("log.txt");
    setup_logging(log_path);

    for n in [1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 120, 500, 1024, 5555, 10000] {
        test_instrumentation(workdir.clone(), n, 8);
    }
}

#[test]
fn test_instrumentation_bits_all() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let workdir = tmp_dir.into_path();
    eprintln!("workdir: {:?}", &workdir);

    let mut log_path = workdir.clone();
    log_path.push("log.txt");
    setup_logging(log_path);

    for n in [1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 120, 500, 1024, 5555, 10000] {
        for access_size in 1..7 {
            test_instrumentation(workdir.clone(), n, access_size);
        }
    }
}
