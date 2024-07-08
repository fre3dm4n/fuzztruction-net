use std::time::Duration;

use fuzztruction_shared::{
    mutation_cache::MutationCache, mutation_cache_entry::MutationCacheEntry,
};
use llvm_stackmap::LLVMInstruction;
use rand::{prelude::SliceRandom, thread_rng};

use crate::{
    fuzzer::{
        worker::FuzzingWorker,
        worker_impl::{
            mutators::{self},
            phases::{inject_debug_mutator, FuzzingPhase},
        },
    },
    mutation_cache_ops::MutationCacheOpsEx,
};

use anyhow::Result;

const PHASE: FuzzingPhase = FuzzingPhase::Discovery;

impl FuzzingWorker {
    fn is_discovery_phase_done(&mut self) -> bool {
        if !self.config.phases.discovery.enabled {
            log::info!("{} phase is not enabled, marking as done", PHASE);
            // If the phase is disabled, it is always "done".
            return true;
        }

        if let Some(timeout) = Some(self.config.phases.discovery.phase_cov_timeout) {
            // If a phase timeout is set, check if we reached it.
            if self
                .stats
                .lock()
                .unwrap()
                .time_since_last_new_path_or_crash()
                .map(|time_passed| time_passed > timeout)
                .unwrap_or(false)
            {
                log::info!("{:?} phase canceled due to timeout of {:?}", PHASE, timeout);
                return true;
            }
        }
        false
    }

    pub fn do_discovery_phase(&mut self) -> Result<()> {
        // We should not get called if this phase is disabled.
        assert!(!self.state.is_phase_done(PHASE));
        assert!(self.state.entry().generation() == 0);

        if self.is_discovery_phase_done() {
            self.state.mark_phase_as_done(PHASE);
            return Ok(());
        }

        self.state.set_phase(PHASE);

        let entry = self.state.entry();
        let trace = entry.stats_ro().trace().unwrap();
        let source = self.source.as_mut().unwrap();

        let mut qe_stats_rw = entry.stats_rw();
        let batch_size = self.config.phases.discovery.batch_size as usize;
        let allocated_patch_points = qe_stats_rw.discovery_allocate(batch_size);
        if allocated_patch_points.len() == 0 {
            qe_stats_rw.mark_phase_done(PHASE);
            log::info!("Entry {:?} finished {:?} phase", entry.id(), PHASE);
            return Ok(());
        }
        drop(qe_stats_rw);

        let allocated_patch_points =
            source.resolve_patch_point_ids(allocated_patch_points.into_iter())?;

        let mut new_mc = MutationCache::from_patchpoints(allocated_patch_points.iter())?;
        unsafe {
            new_mc.remove_uncovered(&trace);
            new_mc.resize_covered_entries(&trace);
            new_mc.union_and_replace(&source.mutation_cache().borrow());
            source.mutation_cache_replace(&new_mc)?;
        }

        let mut candidates = source.mutation_cache().borrow_mut().entries_mut_static();
        candidates.shuffle(&mut rand::thread_rng());

        // Create mutators
        let mut mutations = Vec::<(
            &mut MutationCacheEntry,
            Vec<Box<dyn mutators::Mutator<Item = ()>>>,
        )>::new();

        for candidate in candidates.into_iter() {
            let mut mutators = Vec::new();
            let msk_len = candidate.get_msk_as_slice().len();

            // if matches!(
            //     candidate.llvm_instruction(),
            //     LLVMInstruction::Call | LLVMInstruction::Br
            // ) {
            //     let mutator = mutators::WithTimeout::new(
            //         mutators::FlipBit::new(&mut candidate.get_msk_as_slice()[0..1]),
            //         Duration::from_secs(60),
            //     );
            //     mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            //     inject_debug_mutator(&mut mutators);
            // }

            // if let LLVMInstruction::InjectedCall = candidate.llvm_instruction() {
            //     let mutator = mutators::WithTimeout::new(
            //         mutators::U8Counter::new(&mut candidate.get_msk_as_slice()[0..1]),
            //         Duration::from_secs(60),
            //     );
            //     mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            //     inject_debug_mutator(&mut mutators);
            // } else {
            //     let mutator = mutators::FlipOnce::new(candidate.get_msk_as_slice());
            //     mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            //     inject_debug_mutator(&mut mutators);
            // }

            let mutator = mutators::FlipOnce::new(candidate.get_msk_as_slice());
            mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            inject_debug_mutator(&mut mutators);

            let mutator = mutators::RandomByte1::new(candidate.get_msk_as_slice(), msk_len * 1);
            if let Some(mutator) = mutator {
                let timeout_mutator = mutators::WithTimeout::new(mutator, Duration::from_secs(60));
                mutators.push(Box::new(timeout_mutator) as Box<dyn mutators::Mutator<Item = ()>>);
                inject_debug_mutator(&mut mutators);
            }

            mutators.shuffle(&mut thread_rng());
            let entry = (unsafe { candidate.alias_mut() }, mutators);
            mutations.push(entry);
        }

        let batch_cov_timeout = self.config.phases.discovery.batch_cov_timeout;
        self.fuzz_candidates(mutations, Some(batch_cov_timeout), true)?;

        Ok(())
    }
}
