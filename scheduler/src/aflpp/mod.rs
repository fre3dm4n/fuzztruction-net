#[derive(Debug, Clone, Copy)]
pub enum WorkerId {
    AflMaster,
    AflSlave(usize),
    SymccWorker(usize),
    QsymWorker(usize),
    WeizzMaster,
    WeizzWorker(usize),
}
