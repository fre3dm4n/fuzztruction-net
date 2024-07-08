use std::collections::{HashMap, HashSet};

use anyhow::Result;
use clap::ArgMatches;
use fuzztruction_shared::mutation_cache::MutationCache;
use scheduler::{
    config::Config,
    fuzzer::queue::{Queue, QueueEntryId},
};

pub fn queue_cli(config: &Config, matches: &ArgMatches) -> Result<()> {
    let id_allowlist: Option<Vec<usize>> =
        matches.get_many("id").map(|coll| coll.copied().collect());
    let crashes_only = matches.get_flag("crashes-only");

    let queue_path = config.general.queue_path();
    let queue = Queue::load(&queue_path, None)?;
    let mut entries = queue.entries();
    if crashes_only {
        entries.retain(|e| e.is_crash());
    }

    let mut parent_to_entries: HashMap<QueueEntryId, Vec<QueueEntryId>> = HashMap::new();
    let mut entry_to_parent = HashMap::new();
    for entry in entries.iter() {
        if let Some(parent) = entry.parent_id() {
            parent_to_entries
                .entry(parent)
                .and_modify(|v| v.push(entry.id()))
                .or_default();
            entry_to_parent.insert(entry.id(), parent);
        }
    }

    for entry in entries.iter() {
        if let Some(allowlist) = &id_allowlist {
            if !allowlist.contains(&(entry.id().0 as usize)) {
                continue;
            }
        }

        let _id = entry.id();
        let _mutator = entry.mutator();

        println!("\n");
        dbg!(entry);

        let mut patchpoints = HashSet::new();
        patchpoints.insert(entry.patch_point());

        let mut next_parent_id = entry.parent_id();
        while let Some(parent_id) = next_parent_id {
            let parent = queue.get_id(parent_id);
            patchpoints.insert(parent.patch_point());
            next_parent_id = parent.parent_id();
        }

        patchpoints.remove(&None);
        dbg!(patchpoints);

        if let Some(mutations) = entry.mutations() {
            let mut mc = MutationCache::new().unwrap();
            mc.load_bytes(mutations).unwrap();
            for entry in mc.entries() {
                dbg!(entry);
                println!("msk:");
                hexdump::hexdump(entry.get_msk_as_slice());
                if let Some(padding) = entry.get_padding_as_slice() {
                    println!("padding:");
                    hexdump::hexdump(padding);
                }
            }
        }
    }

    Ok(())
}
