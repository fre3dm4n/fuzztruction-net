use super::{inject_debug_mutator, FuzzingPhase};
use crate::fuzzer::{
    worker::FuzzingWorker,
    worker_impl::mutators::{self, Mutator},
};

use anyhow::Result;
use fuzztruction_shared::mutation_cache_entry::MutationCacheEntry;
use rand::{seq::SliceRandom, thread_rng};

const PHASE: FuzzingPhase = FuzzingPhase::Mutate;

impl FuzzingWorker {
    pub fn do_mutate_phase(&mut self) -> Result<()> {
        self.state.set_phase(PHASE);
        let entry = self.state.entry();

        let source = self.source.as_mut().unwrap();
        let candidates = source.mutation_cache().borrow_mut().entries_mut_static();

        let mut mutations = Vec::<(
            &mut MutationCacheEntry,
            Vec<Box<dyn mutators::Mutator<Item = ()>>>,
        )>::new();

        for candidate in candidates.into_iter() {
            let mut mutators = Vec::new();
            let msk_len = candidate.get_msk_as_slice().len();

            let iterations = match msk_len {
                x if x <= 32 => 32 * x,
                x if x <= 128 => 16 * x,
                _ => 16 * 128,
            };

            if msk_len <= 4 {
                let mutator = mutators::U8Counter::new(candidate.get_msk_as_slice());
                if entry.stats_rw().mark_mutator_done(mutator.mutator_type()) {
                    mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
                    inject_debug_mutator(&mut mutators);
                }
            }

            let mutator = mutators::Havoc::new(candidate.get_msk_as_slice(), 16, iterations);
            mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
            inject_debug_mutator(&mut mutators);

            let mutator = mutators::RandomByte1::new(candidate.get_msk_as_slice(), iterations);
            if let Some(mutator) = mutator {
                mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
                inject_debug_mutator(&mut mutators);
            }

            let mutator = mutators::RandomByte4::new(candidate.get_msk_as_slice(), iterations);
            if let Some(mutator) = mutator {
                mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
                inject_debug_mutator(&mut mutators);
            }

            let mutator = mutators::FlipBit::new(candidate.get_msk_as_slice());
            if entry.stats_rw().mark_mutator_done(mutator.mutator_type()) {
                mutators.push(Box::new(mutator) as Box<dyn mutators::Mutator<Item = ()>>);
                inject_debug_mutator(&mut mutators);
            }

            mutators.shuffle(&mut thread_rng());
            let entry = (unsafe { candidate.alias_mut() }, mutators);
            mutations.push(entry);
        }

        let cov_timeout = self.config.phases.mutate.entry_cov_timeout;
        self.fuzz_candidates(mutations, Some(cov_timeout), false)?;

        Ok(())
    }
}
