use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct LogRecordWrapper {
    pub level: log::Level,
    pub target: String,
    pub message: String,
    pub module_path: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl LogRecordWrapper {
    pub fn from_record(record: &log::Record) -> LogRecordWrapper {
        LogRecordWrapper {
            level: record.level(),
            target: record.metadata().target().to_owned(),
            message: record.args().to_string(),
            module_path: record.module_path().map(|e| e.to_owned()),
            file: record.file().map(|e| e.to_owned()),
            line: record.line(),
        }
    }
}
