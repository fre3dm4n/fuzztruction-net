mod types;
use fuzztruction_shared::util::DEBUG_CHECKS_ENABLED;
pub use types::FuzzingPhase;

use super::mutators::{self, Mutator};

mod run_common;
mod run_phase;
//phases
mod add;
mod combine;
mod discovery;
mod mutate;

// Just for debugging to see whether the unmutated buffer produces the same coverage as the currently fuzzed queue entry during its creation.
// The check whether this holds happend in `check_if_nop_mutator_produced_different_coverage` in `run_common.rs`.
fn inject_debug_mutator(mutators: &mut Vec<Box<dyn Mutator<Item = ()>>>) {
    if DEBUG_CHECKS_ENABLED {
        let mutator = mutators::Nop::new(1);
        mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
    }
}
