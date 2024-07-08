#![warn(clippy::cognitive_complexity)]
#![allow(clippy::vec_box, clippy::identity_op, clippy::single_match)]
#![deny(
    clippy::correctness,
    clippy::cast_possible_wrap,
    unused_lifetimes,
    unused_unsafe,
    single_use_lifetimes,
    missing_debug_implementations
)]
#![feature(
    new_uninit,
    slice_as_chunks,
    seek_stream_len,
    assert_matches,
    thread_id_value,
    core_intrinsics,
    extract_if,
    path_file_prefix
)]

extern crate lazy_static;

pub use fuzztruction_shared::dwarf;
pub use fuzztruction_shared::mutation_cache;
pub use llvm_stackmap;

//pub mod mutation;
pub mod checks;
pub mod io_channels;
pub mod mutation_cache_ops;
pub mod mutation_site;
pub mod sink;
pub mod sink_bitmap;
pub mod source;
pub mod trace;

pub mod config;
pub mod error;
pub mod fuzzer;
pub mod logging;

pub mod constants;

pub mod aflpp;
pub mod competitors;
pub mod networked;
pub mod valgrind;

pub mod coverage;
pub mod finite_integer_set;
pub mod postprocessing;
