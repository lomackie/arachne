use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let cargo = env::var("CARGO").unwrap();

    // The inner cargo build must use a separate target dir to avoid deadlocking
    // on the target/.cargo-lock held by the outer `cargo build` process.
    let ebpf_target_dir = manifest_dir.join("target/ebpf");

    let status = Command::new(&cargo)
        .args([
            "build",
            "--package=arachne-ebpf",
            "--target=bpfel-unknown-none",
            "--release",
            "-Z",
            "build-std=core",
            "--target-dir",
            ebpf_target_dir.to_str().unwrap(),
        ])
        .current_dir(&manifest_dir)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("failed to run cargo build for arachne-ebpf");

    assert!(status.success(), "arachne-ebpf build failed");

    let src = ebpf_target_dir.join("bpfel-unknown-none/release/arachne-ebpf");
    let dst = out_dir.join("arachne-ebpf");
    std::fs::copy(&src, &dst).expect("failed to copy arachne-ebpf ELF");

    println!("cargo:rerun-if-changed=arachne-ebpf/src");
    println!("cargo:rerun-if-changed=arachne-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=arachne-common/src");
    println!("cargo:rerun-if-changed=arachne-common/Cargo.toml");
}
