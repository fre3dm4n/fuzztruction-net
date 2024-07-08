use glob::glob;
use std::{path::PathBuf, process};

fn main() {
    register_files_for_change_monitoring();
    build_llvm_pass();
}

fn register_files_for_change_monitoring() {
    let pass_folder = glob(&format!("{}/../pass/**", env!("CARGO_MANIFEST_DIR"))).unwrap();
    for p in pass_folder.flatten() {
        println!("cargo:rerun-if-changed={}", p.to_str().unwrap());
    }
}

fn build_llvm_pass() {
    println!("Building source llvm pass...");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut cmd = process::Command::new("make");
    let cwd = PathBuf::from(manifest_dir).join("../pass");
    cmd.current_dir(cwd);
    cmd.spawn().unwrap();
}
