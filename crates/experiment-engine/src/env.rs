//! Execution environment captured with every experiment and benchmark.

use serde_json::{Value, json};

/// Files whose content determines experiment results. Their SHA-256 is the
/// source fingerprint stored with every record (works without git).
const SOURCES: &[(&str, &str)] = &[
    ("crates/sha256-core/src/lib.rs", include_str!("../../sha256-core/src/lib.rs")),
    ("crates/sha256d/src/lib.rs", include_str!("../../sha256d/src/lib.rs")),
    ("crates/bitcoin-header/src/lib.rs", include_str!("../../bitcoin-header/src/lib.rs")),
    ("crates/differential-engine/src/lib.rs", include_str!("../../differential-engine/src/lib.rs")),
    ("crates/statistical-engine/src/lib.rs", include_str!("../../statistical-engine/src/lib.rs")),
    ("crates/verification/src/lib.rs", include_str!("../../verification/src/lib.rs")),
    ("crates/experiment-engine/src/lib.rs", include_str!("lib.rs")),
    ("crates/experiment-engine/src/reduced_round.rs", include_str!("reduced_round.rs")),
    ("crates/experiment-engine/src/differential.rs", include_str!("differential.rs")),
    ("crates/experiment-engine/src/statistical.rs", include_str!("statistical.rs")),
    ("crates/experiment-engine/src/smt.rs", include_str!("smt.rs")),
    ("crates/experiment-engine/src/characteristic.rs", include_str!("characteristic.rs")),
    ("crates/experiment-engine/src/algebraic.rs", include_str!("algebraic.rs")),
    ("crates/experiment-engine/src/schedule.rs", include_str!("schedule.rs")),
    ("crates/experiment-engine/src/smt_scaling.rs", include_str!("smt_scaling.rs")),
    ("crates/experiment-engine/src/multiseed.rs", include_str!("multiseed.rs")),
    ("crates/experiment-engine/src/hardware.rs", include_str!("hardware.rs")),
    ("crates/differential-engine/src/characteristic.rs", include_str!("../../differential-engine/src/characteristic.rs")),
    ("crates/algebraic-engine/src/lib.rs", include_str!("../../algebraic-engine/src/lib.rs")),
    ("crates/hardware-model/src/lib.rs", include_str!("../../hardware-model/src/lib.rs")),
    ("crates/experiment-engine/src/characteristic_audit.rs", include_str!("characteristic_audit.rs")),
    ("crates/experiment-engine/src/trail_search.rs", include_str!("trail_search.rs")),
    ("crates/experiment-engine/src/nonce_atlas.rs", include_str!("nonce_atlas.rs")),
    ("crates/experiment-engine/src/trail_sat.rs", include_str!("trail_sat.rs")),
    ("crates/experiment-engine/src/quantum_model.rs", include_str!("quantum_model.rs")),
    ("crates/experiment-engine/src/board.rs", include_str!("board.rs")),
    ("crates/experiment-engine/src/work_sharing.rs", include_str!("work_sharing.rs")),
    ("crates/experiment-engine/src/header_atlas.rs", include_str!("header_atlas.rs")),
    ("crates/experiment-engine/src/evolved_rules.rs", include_str!("evolved_rules.rs")),
    ("crates/experiment-engine/src/grover_circuit.rs", include_str!("grover_circuit.rs")),
    ("crates/experiment-engine/src/template_luck.rs", include_str!("template_luck.rs")),
    ("crates/mining-engine/src/p2p.rs", include_str!("../../mining-engine/src/p2p.rs")),
    ("research/differential-cryptanalysis/trail_sat.py", include_str!("../../../research/differential-cryptanalysis/trail_sat.py")),
    ("research/algebraic-models/smt_reduced_round.py", include_str!("../../../research/algebraic-models/smt_reduced_round.py")),
    ("research/algebraic-models/smt_scaling.py", include_str!("../../../research/algebraic-models/smt_scaling.py")),
    ("research/differential-cryptanalysis/trail_audit.py", include_str!("../../../research/differential-cryptanalysis/trail_audit.py")),
    // Benchmarks and mining: kernels, backends, protocol code and the CLI that drives them.
    ("crates/bitcoin-header/src/block.rs", include_str!("../../bitcoin-header/src/block.rs")),
    ("crates/cpu-backend/src/lib.rs", include_str!("../../cpu-backend/src/lib.rs")),
    ("crates/gpu-backend/src/lib.rs", include_str!("../../gpu-backend/src/lib.rs")),
    ("crates/gpu-backend/src/v2.rs", include_str!("../../gpu-backend/src/v2.rs")),
    ("gpu/wgsl/sha256d.wgsl", include_str!("../../../gpu/wgsl/sha256d.wgsl")),
    ("crates/mining-engine/src/lib.rs", include_str!("../../mining-engine/src/lib.rs")),
    ("crates/mining-engine/src/regtest.rs", include_str!("../../mining-engine/src/regtest.rs")),
    ("crates/mining-engine/src/rpc.rs", include_str!("../../mining-engine/src/rpc.rs")),
    ("apps/research-cli/src/main.rs", include_str!("../../../apps/research-cli/src/main.rs")),
];

fn fingerprint<'a>(files: impl Iterator<Item = (&'a str, Vec<u8>)>) -> String {
    let mut all = Vec::new();
    for (path, text) in files {
        all.extend_from_slice(path.as_bytes());
        all.push(0);
        // Normalise line endings so checkouts with CRLF give the same fingerprint.
        all.extend(text.into_iter().filter(|&b| b != b'\r'));
        all.push(0);
    }
    bitcoin_header::hex_encode(&sha256_core::sha256(&all))
}

/// Fingerprint of the sources this binary was compiled from.
pub fn source_fingerprint() -> String {
    fingerprint(SOURCES.iter().map(|(p, t)| (*p, t.as_bytes().to_vec())))
}

/// Whether `git_commit` describes this binary exactly: the same files on disk
/// hash to the compiled fingerprint and git reports none of them modified.
pub fn binary_matches_commit() -> bool {
    let root = research_storage::workspace_root();
    let on_disk = SOURCES.iter().map(|(p, _)| std::fs::read(root.join(p)).map(|b| (*p, b)));
    let Ok(files) = on_disk.collect::<Result<Vec<_>, _>>() else { return false };
    if fingerprint(files.into_iter()) != source_fingerprint() {
        return false;
    }
    let paths: Vec<&str> = SOURCES.iter().map(|(p, _)| *p).collect();
    std::process::Command::new("git")
        .args(["status", "--porcelain", "--"])
        .args(&paths)
        .current_dir(&root)
        .output()
        .is_ok_and(|o| o.status.success() && o.stdout.is_empty())
}

#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)]
pub fn cpu_brand() -> Option<String> {
    use std::arch::x86_64::__cpuid;
    // SAFETY: CPUID is available on every x86-64 CPU.
    if unsafe { __cpuid(0x8000_0000) }.eax < 0x8000_0004 {
        return None;
    }
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002u32..=0x8000_0004 {
        // SAFETY: leaf checked against the maximum extended leaf above.
        let r = unsafe { __cpuid(leaf) };
        for reg in [r.eax, r.ebx, r.ecx, r.edx] {
            bytes.extend_from_slice(&reg.to_le_bytes());
        }
    }
    Some(String::from_utf8_lossy(&bytes).trim_matches('\0').trim().to_string())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn cpu_brand() -> Option<String> {
    None
}

pub fn cpu_features() -> Value {
    #[cfg(target_arch = "x86_64")]
    {
        json!({
            "sse4.1": std::is_x86_feature_detected!("sse4.1"),
            "avx2": std::is_x86_feature_detected!("avx2"),
            "avx512f": std::is_x86_feature_detected!("avx512f"),
            "sha_ni": std::is_x86_feature_detected!("sha"),
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        json!({})
    }
}

/// `git rev-parse HEAD` in the workspace, when it is a git checkout.
pub fn git_commit() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(research_storage::workspace_root())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn environment() -> Value {
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpu": cpu_brand(),
        "cpu_features": cpu_features(),
        "logical_cpus": std::thread::available_parallelism().map_or(1, |n| n.get()),
        "rayon_threads": rayon::current_num_threads(),
        "rustc": env!("BMR_RUSTC_VERSION"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "bmr_version": env!("CARGO_PKG_VERSION"),
        "source_fingerprint": source_fingerprint(),
        "git_commit": git_commit(),
        "binary_matches_commit": binary_matches_commit(),
    })
}
