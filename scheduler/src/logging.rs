//! Functions related to logging.

use byte_unit::n_mib_bytes;
use fern::colors::{Color, ColoredLevelConfig};
use file_rotate::{compression::Compression, suffix::AppendCount, ContentLimit, FileRotate};
use log::{self};
use std::{
    panic,
    path::{Path, PathBuf},
    process,
    str::FromStr,
};

use ansi_term::Colour::Red;
use anyhow::{Context, Result};

/// Setup the global logger and only log messages of level `log_level`
/// or higher.
pub fn setup_logger(log_path: &Path, log_level: &str) -> Result<()> {
    let rotating_log_file = FileRotate::new(
        log_path,
        AppendCount::new(5),
        ContentLimit::BytesSurpassed(n_mib_bytes!(256).try_into().unwrap()),
        Compression::None,
        #[cfg(unix)]
        None,
    );

    fern::Dispatch::new()
        .format(|out, message, record| {
            let message = format!("{}", message);
            if record.key_values().get("from_agent".into()).is_some() {
                let color = Color::Green;
                out.finish(format_args!(
                    "\x1B[{}m{}\x1B[0m",
                    color.to_fg_str(),
                    message
                ));
            } else {
                let level_colors = ColoredLevelConfig::new()
                    .error(Color::Red)
                    .warn(Color::Yellow);

                out.finish(format_args!(
                    "{}[{}][{:#?}][{}:{}][{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d %H:%M:%S:%f]"),
                    record.target().split("::").next().unwrap_or("?"),
                    unsafe { libc::gettid() },
                    record
                        .file()
                        .map(|s| PathBuf::from(s)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned())
                        .unwrap_or_else(|| "?".to_owned()),
                    record
                        .line()
                        .map(|l| format!("{}", l))
                        .unwrap_or_else(|| "?".to_owned()),
                    level_colors.color(record.level()),
                    message,
                ))
            }
        })
        .level(
            log::LevelFilter::from_str(log_level)
                .context(format!("'{}' is not a valid log level", log_level))?,
        )
        .chain(std::io::stdout())
        .chain(fern::Output::writer(Box::new(rotating_log_file), "\n"))
        .apply()?;
    Ok(())
}

fn panic_hook(info: &panic::PanicInfo<'_>) {
    log::error!("{}", Red.paint(format!("\nPanic: {:#?}", info)));
    if let Some(location) = info.location() {
        let file = location.file();
        let line = location.line();
        log::error!("{}", Red.paint(format!("Location: {}:{}", file, line)));
    }
    process::abort();
}

pub fn setup_panic_logging() {
    log::info!("Panics are logged via log::error");
    panic::set_hook(Box::new(panic_hook));
}
