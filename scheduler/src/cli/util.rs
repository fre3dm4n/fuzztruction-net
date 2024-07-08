use std::{str::FromStr, time};

use regex::Regex;

pub struct CliDuration(pub time::Duration);

impl FromStr for CliDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = Regex::new("^([0-9]+)(ms|s|m|h|d|a)$").unwrap();
        let matches = re.captures(s).ok_or(format!(
            "Invalid duration format ({})! Supported are <amount>(ms|s|m|h|d)",
            s
        ))?;
        if matches.len() != 3 {
            return Err("Failed to match components".to_owned());
        }

        let amount = matches.get(1).unwrap().as_str();
        let suffix = matches.get(2).unwrap().as_str();

        let amount = u64::from_str(amount).unwrap();

        let seconds = match suffix {
            "ms" => amount,
            "s" => amount * 1000,
            "m" => amount * 60 * 1000,
            "h" => amount * 3600 * 1000,
            "d" => amount * 3600 * 24 * 1000,
            "a" => amount * 3600 * 24 * 365 * 1000,
            _ => unreachable!(),
        };
        Ok(CliDuration(time::Duration::from_millis(seconds)))
    }
}
