//! SMT experiment: can a bit-vector solver (Z3) find a nonce meeting a target
//! for reduced-round SHA-256d faster than brute force?
//!
//! The model lives in `research/algebraic-models/smt_reduced_round.py` and is
//! run as a subprocess. Every nonce it reports is re-verified here with two
//! independent SHA-256 implementations.

use crate::{Definition, Outcome, Verification, p_rounds, p_u64};
use anyhow::{Context, Result, bail};
use bitcoin_header::{HeaderMidstate, Target, hash_number_words};
use serde_json::{Value, json};
use statistical_engine::SplitMix64;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;
use verification::independent;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-SMT-01",
        primitive: crate::primitive::HEADER,
        name: "Z3 bit-vector nonce search on reduced-round SHA-256d",
        version: 1,
        hypothesis: "For some round count r, a QF_BV SMT solver finds a nonce whose r-round SHA-256d header hash has k leading zero bits in less time than brute-force search on one CPU core.",
        null_hypothesis: "Solver time exceeds the brute-force time for every instance (no algebraic shortcut exploitable by a generic SMT solver).",
        assumptions: &[
            "Midstate (first header block) is concrete; only the 32-bit nonce is symbolic.",
            "Brute force uses the generic reduced-round midstate path on one core (no SIMD); it is the honest baseline for 'expected work'.",
            "Solver timing includes model construction inside Z3 but not Python start-up.",
            "Solver results are only trusted after independent re-verification.",
        ],
        baseline: "Single-thread brute force from nonce 0; expected 2^k hash evaluations.",
        methodology: "For each round count and instance, build a random header, compute the r-round midstate, time brute force to the first valid nonce, then ask Z3 for any valid nonce with a timeout. A configuration is flagged only when the solver returns a verified nonce faster than brute force.",
        implementation: &["research/algebraic-models/smt_reduced_round.py (z3-solver)", "bitcoin_header::HeaderMidstate::with_rounds"],
        dataset: "`instances` random 80-byte headers per round count from SplitMix64::stream(seed, instance).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": if quick { json!([4]) } else { json!([4, 8, 12, 16]) },
        "zero_bits": 8,
        "instances": if quick { 1 } else { 2 },
        "timeout_ms": if quick { 10000 } else { 30000 },
        "reproduce": false,
    })
}

fn python() -> String {
    std::env::var("BMR_PYTHON").unwrap_or_else(|_| "python".into())
}

/// `Some(version)` when Python with the z3 module is available.
pub fn z3_version() -> Option<String> {
    let out = Command::new(python())
        .args(["-I", "-c", "import z3; print(z3.get_version_string())"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// k leading zero bits of the hash number (most significant word first).
pub(crate) fn meets(words: &[u32; 8], k: u32) -> bool {
    words[0] >> (32 - k) == 0
}

pub(crate) struct Brute {
    pub nonce: Option<u32>,
    pub hashes: u64,
    pub seconds: f64,
}

/// Single-thread scan from nonce 0, capped at 2^(k+12) nonces (4096x the
/// expected work): reduced-round structure can make a target unreachable.
pub(crate) fn brute(mid: &HeaderMidstate, k: u32) -> Brute {
    let t = Instant::now();
    let mut hashes = 0;
    for nonce in (0..=u32::MAX).take((1u64 << (k + 12)).min(1 << 32) as usize) {
        hashes += 1;
        if meets(&hash_number_words(&mid.hash_words(nonce)), k) {
            return Brute { nonce: Some(nonce), hashes, seconds: t.elapsed().as_secs_f64() };
        }
    }
    Brute { nonce: None, hashes, seconds: t.elapsed().as_secs_f64() }
}

/// A solver nonce counts only if both SHA-256 implementations confirm it.
pub(crate) fn nonce_valid(header: &[u8; 80], mid: &HeaderMidstate, rounds: usize, k: u32, nonce: u32) -> bool {
    let mut h = *header;
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    meets(&hash_number_words(&mid.hash_words(nonce)), k)
        && meets(&Target::from_hash(&independent::Sha256::default().sha256d(&h, rounds)).words(), k)
}

/// Inconsistency of one solver answer, if any.
pub(crate) fn answer_problem(status: &Value, nonce_valid: &Value, brute_nonce: &Value) -> Option<&'static str> {
    if status == "sat" && nonce_valid != true {
        Some("invalid solver nonce")
    } else if status == "unsat" && !brute_nonce.is_null() {
        Some("unsat contradicts a brute-force hit (model bug)")
    } else {
        None
    }
}

/// Run `research/algebraic-models/<script>` with `instance` on stdin and parse its JSON stdout.
pub(crate) fn run_script(script: &str, instance: &Value) -> Result<Value> {
    let path = research_storage::workspace_root().join("research").join("algebraic-models").join(script);
    let mut child = Command::new(python())
        .arg("-I")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting python")?;
    child.stdin.take().context("stdin")?.write_all(instance.to_string().as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("solver script failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).context("solver output is not JSON")
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let k = p_u64(params, "zero_bits")? as u32;
    anyhow::ensure!((1..=32).contains(&k), "zero_bits must be 1..=32");
    let instances = p_u64(params, "instances")?;
    let timeout_ms = p_u64(params, "timeout_ms")?;
    let Some(z3) = z3_version() else {
        return Ok(Outcome::skipped(format!("`{} -I -c \"import z3\"` failed; install with `pip install z3-solver`", python())));
    };
    let (mut obs, mut det, mut flags) = (Vec::new(), Vec::new(), Vec::new());
    for &r in &rounds {
        for i in 0..instances {
            let header: [u8; 80] = SplitMix64::stream(seed, i).bytes();
            let mid = HeaderMidstate::with_rounds(&header, r);
            let b = brute(&mid, k);
            let rate = b.hashes as f64 / b.seconds.max(1e-9);
            let inst = json!({
                "midstate": mid.state, "tail": mid.tail, "rounds": r, "zero_bits": k,
                "timeout_ms": timeout_ms, "seed": seed.wrapping_add(i),
            });
            let s = run_script("smt_reduced_round.py", &inst)?;
            let solver_seconds = s["solve_seconds"].as_f64().unwrap_or(f64::NAN);
            let status = s["status"].as_str().unwrap_or("error").to_string();
            let solver_nonce = s["nonce"].as_u64().map(|n| n as u32);
            let valid = solver_nonce.map(|n| nonce_valid(&header, &mid, r, k, n));
            let faster = status == "sat" && valid == Some(true) && solver_seconds < b.seconds;
            flags.push((r, faster));
            det.push(json!({ "rounds": r, "instance": i, "midstate": mid.state, "brute_force_nonce": b.nonce, "brute_force_hashes": b.hashes }));
            obs.push(json!({
                "rounds": r,
                "instance": i,
                "zero_bits": k,
                "brute_force": { "nonce": b.nonce, "hashes": b.hashes, "seconds": b.seconds, "expected_hashes": 2f64.powi(k as i32) },
                "solver": { "status": status, "nonce": solver_nonce, "nonce_valid": valid, "seconds": solver_seconds, "timeout_ms": timeout_ms, "z3_version": z3 },
                "solver_cost_in_hashes": solver_seconds * rate,
                "solver_over_brute_force_time": solver_seconds / b.seconds.max(1e-9),
                "solver_faster": faster,
            }));
        }
    }
    let sat = obs.iter().filter(|o| o["solver"]["status"] == "sat").count();
    let best = obs.iter().filter_map(|o| o["solver_over_brute_force_time"].as_f64()).fold(f64::INFINITY, f64::min);
    let summary = vec![
        format!("Solver returned a nonce for {sat} of {} instances within {timeout_ms} ms.", obs.len()),
        format!("Best solver/brute-force time ratio: {best:.3e} (>1 means the solver was slower)."),
        format!("Target: {k} leading zero bits; brute force needs about 2^{k} hashes, so a solver shortcut would have to beat microseconds."),
    ];
    Ok(Outcome::new(json!(obs), json!(det), flags, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding from smt-0001 (reduced-round only): with 4 rounds per
    /// compression, inner rounds 0..2 are nonce-free, so a4 = c + W3 and
    /// e4 = c' + W3 with W3 = bswap(nonce); the outer H7 = IV7 + e0 is then
    /// exactly K + bswap(nonce) mod 2^32. The hash number's top byte is H7's
    /// low byte, i.e. it depends only on the nonce's top byte.
    #[test]
    fn four_round_h7_is_affine_in_the_nonce() {
        for h in 0..16u64 {
            let header: [u8; 80] = SplitMix64::stream(9, h).bytes();
            let mid = HeaderMidstate::with_rounds(&header, 4);
            let k = mid.hash_words(0)[7].wrapping_sub(0u32.swap_bytes());
            let mut rng = SplitMix64::stream(10, h);
            for _ in 0..256 {
                let n = rng.next_u32();
                assert_eq!(mid.hash_words(n)[7], k.wrapping_add(n.swap_bytes()));
            }
        }
        // Not true at 5 rounds.
        let mid = HeaderMidstate::with_rounds(&SplitMix64::stream(9, 0).bytes(), 5);
        let k = mid.hash_words(0)[7];
        assert!((1..256u32).any(|n| mid.hash_words(n)[7] != k.wrapping_add(n.swap_bytes())));
    }
}

/// Every solver nonce must be valid; `unsat` contradicts a brute-force hit.
pub fn verify(_: &Value, _: u64, outcome: &Outcome) -> Result<Verification> {
    let problems: Vec<String> = outcome
        .observations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|o| {
            let p = answer_problem(&o["solver"]["status"], &o["solver"]["nonce_valid"], &o["brute_force"]["nonce"])?;
            Some(format!("r{} i{}: {p}", o["rounds"], o["instance"]))
        })
        .collect();
    Ok(Verification {
        method: "solver nonces recomputed with HeaderMidstate (sha256-core) and with verification::independent over the full header; unsat answers cross-checked against brute force".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "all solver answers consistent".into() } else { problems.join("; ") },
    })
}
