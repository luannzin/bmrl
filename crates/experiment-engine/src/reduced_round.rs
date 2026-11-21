//! Reduced-round avalanche experiment: at which round count does the SHA-256
//! compression function stop being distinguishable from a random function
//! by first-order avalanche statistics?

use crate::{Definition, Outcome, Verification, p_f64, p_rounds, p_u64};
use anyhow::Result;
use differential_engine::{IN_BITS, OUT_BITS, analyze_avalanche, avalanche, sample};
use serde_json::{Value, json};
use statistical_engine::{Z95, wilson};
use verification::independent;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-AVAL-01",
        primitive: crate::primitive::COMPRESSION,
        name: "Strict avalanche criterion of reduced-round SHA-256 compression",
        version: 1,
        hypothesis: "For some round counts r < 64, flipping one message bit flips some output bit of the r-round SHA-256 compression function (with feed-forward) with probability measurably different from 1/2, or the Hamming weight of the output difference deviates from Binomial(256, 1/2).",
        null_hypothesis: "For every tested r, each of the 512x256 flip probabilities is 1/2 and output-difference weights follow Binomial(256, 1/2), as for a random function.",
        assumptions: &[
            "Chaining value and message block are uniform and independent (SplitMix64 streams).",
            "Flip counts of a cell are Binomial(n, p); normal approximation for |z| (n >= 1024).",
            "Weight histogram tested by chi-square with bins merged to expected count >= 5.",
            "Family-wise error controlled by Bonferroni over 131072 cells and over round counts.",
            "Round-reduced variants keep the message schedule and the feed-forward; only the round loop is cut.",
        ],
        baseline: "Ideal random function: every flip probability 1/2; weight ~ Binomial(256, 1/2).",
        methodology: "For each round count r and each of n random (cv, block) pairs, compute the r-round compression of the block and of the 512 single-bit variants. Count, per (input bit, output bit), how often the output bit flips; histogram the output-difference weight. A configuration is flagged when any cell is Bonferroni-significant or the weight chi-square rejects at alpha / (number of round counts).",
        implementation: &["differential_engine::avalanche", "differential_engine::analyze_avalanche", "sha256_core::compress_words"],
        dataset: "n random (chaining value, message block) pairs per round count; sample i drawn from SplitMix64::stream(seed, i).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": [4, 8, 12, 16, 17, 18, 19, 20, 21, 22, 24, 32, 64],
        "samples": if quick { 1024 } else { 16384 },
        "alpha": 0.01,
        "reproduce": true,
    })
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let samples = p_u64(params, "samples")?;
    let alpha = p_f64(params, "alpha")?;
    let alpha_cfg = alpha / rounds.len() as f64;
    let (mut per_round, mut det, mut flags) = (Vec::new(), Vec::new(), Vec::new());
    for &r in &rounds {
        let a = avalanche(r, samples, seed);
        let s = analyze_avalanche(&a, alpha_cfg);
        flags.push((r, s.distinguishable));
        let (ib, ob, c) = s.worst_pair;
        let flip_bytes: Vec<u8> = a.flips.iter().flat_map(|c| c.to_le_bytes()).collect();
        det.push(json!({
            "rounds": r,
            "flips_sha256": bitcoin_header::hex_encode(&sha256_core::sha256(&flip_bytes)),
            "weight_hist": a.weight_hist,
        }));
        per_round.push(json!({
            "rounds": r,
            "samples": samples,
            "trials": samples * IN_BITS as u64,
            "mean_flip_probability": s.mean_flip_probability,
            "max_bias": s.max_bias,
            "max_abs_z": s.max_abs_z,
            "worst_pair": {
                "input_bit": ib, "message_word": ib / 32, "bit_in_word": ib % 32,
                "output_bit": ob, "output_word": ob / 32,
                "flip_probability": c as f64 / samples as f64,
                "ci95": wilson(c, samples, Z95),
            },
            "bonferroni_significant_pairs": s.significant_pairs,
            "never_flipped_pairs": s.never_flipped_pairs,
            "always_flipped_pairs": s.always_flipped_pairs,
            "inert_message_words": s.inert_message_words,
            "weight_chi_square": { "statistic": s.weight_gof.statistic, "df": s.weight_gof.df, "p_value": s.weight_gof.p_value },
            "alpha_per_configuration": alpha_cfg,
            "deviation_detected": s.distinguishable,
        }));
    }
    let mut summary = Vec::new();
    if let Some(last) = flags.iter().filter(|f| f.1).map(|f| f.0).max() {
        summary.push(format!("Largest round count with a detectable avalanche deviation: {last}."));
    }
    let clean: Vec<usize> = flags.iter().filter(|f| !f.1).map(|f| f.0).collect();
    if let Some(first) = clean.iter().min() {
        summary.push(format!("Smallest tested round count with no detectable deviation: {first} (clean round counts: {clean:?})."));
    }
    summary.push(format!(
        "Sample size n = {samples} per round count; with Bonferroni correction a single-cell bias must exceed roughly {:.4} to be detected, so smaller biases at larger round counts are not excluded.",
        statistical_engine::z_for_two_sided(alpha_cfg / (IN_BITS * OUT_BITS) as f64) * 0.5 / (samples as f64).sqrt()
    ));
    Ok(Outcome::new(json!(per_round), json!(det), flags, summary))
}

/// Recompute the first samples with the independent SHA-256 and compare all counts.
pub fn verify(params: &Value, seed: u64, _: &Outcome) -> Result<Verification> {
    let rounds = p_rounds(params)?;
    let n = p_u64(params, "samples")?.min(64);
    let ind = independent::Sha256::default();
    let mut mismatched = Vec::new();
    for &r in &rounds {
        let engine = avalanche(r, n, seed);
        let mut flips = vec![0u64; IN_BITS * OUT_BITS];
        let mut hist = vec![0u64; OUT_BITS + 1];
        for i in 0..n {
            let (cv, m) = sample(seed, i);
            let base = ind.compress(&cv, &m, r);
            for j in 0..IN_BITS {
                let mut m2 = m;
                m2[j / 32] ^= 1 << (j % 32);
                let out = ind.compress(&cv, &m2, r);
                let mut weight = 0;
                for o in 0..OUT_BITS {
                    if (base[o / 32] ^ out[o / 32]) >> (o % 32) & 1 == 1 {
                        flips[j * OUT_BITS + o] += 1;
                        weight += 1;
                    }
                }
                hist[weight] += 1;
            }
        }
        if flips != engine.flips || hist != engine.weight_hist {
            mismatched.push(r);
        }
    }
    Ok(Verification {
        method: "independent SHA-256 (verification::independent, constants derived from primes) recomputes all flip counts and weight histograms for the first samples of every round count".into(),
        passed: mismatched.is_empty(),
        detail: format!("{n} samples x {} round counts; mismatching round counts: {mismatched:?}", rounds.len()),
    })
}
