use std::time::Duration;

/// The maximum number of supported patch points. This limit to allow us to
/// efficiently store PatchPointIDs via bitmaps.
/// Programmes containing more than this limit, will raise an assertion.
/// In this case, the limit might simply be raised to the desired value, however,
/// mind that this will increase the overall memory footprint.
pub const MAX_PATCHPOINT_CNT: usize = 400_000;
pub const MAX_QUEUE_ENTRY_CNT: usize = 100000;
pub const EXECUTION_TIMEOUT_MULTIPLYER: f64 = 2.0;
pub const AVG_EXECUTION_TIME_STABILIZATION_VALUE: u32 = 100;
/// Interval between:
///     - checks whether the worker was terminated
///     - state updates (e.g., progress of the current mutator)
pub const FUZZING_LOOP_UPDATE_INTERVAL: Duration = Duration::from_secs(20);

/// Max execution count for one particular mutation site.
/// Sites executed more often than this are ignored.
pub const TRACE_EXEC_CNT_LIMIT: u64 = 16384;
pub const CALIBRATION_MEASURE_CYCLES: u64 = 20;
pub const DEFAULT_CALIBRATION_TIMEOUT: Duration = Duration::from_secs(1);

pub const DYNAMIC_JOB_SPAWNING_MAX_JOBS: usize = 100;
pub const DYNAMIC_JOB_SPAWNING_CPU_THRESHOLD: f32 = 80.0;
pub const DYNAMIC_JOB_SPAWNING_INITIAL_DELAY: Duration = Duration::from_secs(300);
pub const DYNAMIC_JOB_SPAWNING_DELAY: Duration = Duration::from_secs(120);
pub const MAX_WORKER_RESTART_CNT: usize = 100;

pub const MAX_QUEUE_DUMP_THREADS: usize = 16;
