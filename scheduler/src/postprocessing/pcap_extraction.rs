use std::{
    fs,
    sync::{atomic::AtomicBool, Arc},
};

use crate::{config::Config, fuzzer::queue::Queue};
use anyhow::Result;

pub fn extract_pcaps(config: &Config, _exit_requested: Arc<AtomicBool>) -> Result<()> {
    let queue_path = config.general.queue_path();
    log::info!("Loading queue at {queue_path:?} from disk...");
    let queue = Queue::load(&queue_path, None)?;

    let queue_len = queue.len();
    log::info!("Queue has {} entries", queue_len);

    let pcap_folder = config.general.pcap_path();
    let _ = fs::remove_dir_all(&pcap_folder);
    fs::create_dir(&pcap_folder).unwrap();

    let mut failed_ctr = 0;
    for entry in queue.iter() {
        let pcap = entry.pcap();
        let pcap = if let Some(pcap) = pcap {
            pcap
        } else {
            log::warn!(
                "Skipping entry {:?} since it does not contain a pcap recording.",
                entry.id()
            );
            failed_ctr += 1;
            continue;
        };
        let is_crash = entry.is_crash();

        let dst_name = format!(
            "id:{},ts:{},is_crash={}.pcap",
            entry.id().0,
            entry.creation_ts().unwrap_or(0),
            is_crash
        );
        let mut dst_path = pcap_folder.clone();
        dst_path.push(dst_name);

        fs::write(dst_path, pcap).unwrap();
    }

    log::info!(
        "Successfully extracted {} of {} recordings",
        queue_len - failed_ctr,
        queue_len
    );

    Ok(())
}
