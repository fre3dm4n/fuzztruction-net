use std::process::Command;

use anyhow::Result;
use clap::ArgMatches;
use scheduler::{config::Config, source::Source};

pub fn patchpoint_inspection(config: &Config, matches: &ArgMatches) -> Result<()> {
    let id_allowlist: Option<Vec<usize>> =
        matches.get_many("id").map(|coll| coll.copied().collect());

    let mut source = Source::from_config(config, None, None).unwrap();
    source.start().expect("Failed to start source");

    let patchpoints = source.get_patchpoints()?;

    for patchpoint in patchpoints.iter() {
        if let Some(allowlist) = &id_allowlist {
            if !allowlist.contains(&(patchpoint.id().0 as usize)) {
                continue;
            }
        }

        println!("Patch Point {}", patchpoint.id().0);
        println!("{:#?}", patchpoint);
        let address = patchpoint.address();
        println!("Address: 0x{:x}", address);
        let address_hex = format!("0x{:x}", address);
        Command::new("addr2line")
            .args([
                "-e",
                &patchpoint.mapping().pathname.as_ref().unwrap(),
                &address_hex,
            ])
            .spawn()?
            .wait_with_output()?;

        println!("\n\n");
    }

    Ok(())
}
