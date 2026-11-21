//! Multi-seed statistical testing against random-function baselines.
//!
//! The same test battery runs on many independent seeds for SHA-256 (single),
//! SHA-256d of Bitcoin headers over the nonce, SHA-256d of independent random
//! inputs, and a non-SHA pseudo-random function (negative control). Under the
//! null hypothesis each test's p-values are Uniform(0, 1) across seeds; a
//! Kolmogorov–Smirnov test on those p-values is the decision statistic. A
//! deviation in a single seed is therefore never a finding, and the control
//! measures the battery's own false-positive behaviour.

use crate::statistical::Counts;
use crate::{Definition, FULL_ROUNDS, Outcome, Verification, p_f64, p_rounds, p_u64};
use anyhow::{Context, Result};
use bitcoin_header::{HeaderMidstate, hash_number_words};
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::compress_words;
use statistical_engine::{SplitMix64, Z95, ks_uniform, mean_ci95, wilson};

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-STAT-02",
        primitive: "sha256,sha256d,bitcoin-header-sha256d",
        name: "Multi-seed random-function tests of SHA-256, SHA-256d and header hashing",
        version: 1,
        hypothesis: "Across many independent seeds, the p-values of bit-frequency, leading-zero and consecutive-input tests on r-round SHA-256, SHA-256d of headers over the nonce, or SHA-256d of random inputs are not Uniform(0, 1), while a non-SHA pseudo-random control is.",
        null_hypothesis: "For every function and round count, each test's p-values across seeds are Uniform(0, 1) (KS test), as for the control.",
        assumptions: &[
            "Seeds are independent (SplitMix64 streams of the derived seed).",
            "Per-seed tests: Šidák-adjusted minimum bit p-value (256 bits), leading-zero chi-square against P(lz = k) = 2^-(k+1), consecutive-input bit-agreement chi-square against Binomial(256, 1/2).",
            "Decision: KS test of the per-seed p-values, Bonferroni over functions x round counts x 3 tests.",
            "Control: 256-bit outputs of SplitMix64 keyed by (seed, input index); unrelated to SHA-256.",
            "SHA-256 (single) is evaluated on the same header/nonce inputs as SHA-256d, digest read as a little-endian number like a block hash.",
        ],
        baseline: "Random function: uniform p-values; target hit rate 2^-k; the control function measured under the same battery.",
        methodology: "For each seed, function and round count, hash headers_per_seed x nonces_per_header inputs and compute the three p-values and the 8-bit target hit rate. Across seeds, report KS statistics, the fraction of seeds with p < 0.01 (Wilson 95% interval) and the mean hit-rate ratio with a 95% interval.",
        implementation: &["experiment_engine::statistical::Counts", "bitcoin_header::HeaderMidstate::with_rounds", "statistical_engine::ks_uniform"],
        dataset: "Per seed s: headers from SplitMix64::stream(derived(seed, s), h); random-input variant draws a fresh header and nonce per input.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "functions": ["sha256-header-nonce", "sha256d-header-nonce", "sha256d-random-inputs"],
        "rounds": [16, 20, 24, 64],
        "seeds": if quick { 8 } else { 32 },
        "headers_per_seed": 8,
        "nonces_per_header": if quick { 2048 } else { 16384 },
        "alpha": 0.01,
        "reproduce": true,
    })
}

fn derived(seed: u64, s: u64) -> u64 {
    SplitMix64::stream(seed, 0x5eed_0000 + s).next_u64()
}

/// Statistics of one (function, rounds, seed) cell. `rounds == None` is the control.
fn cell(function: &str, rounds: Option<usize>, seed: u64, headers: u64, per: u64) -> Result<Counts> {
    let mut c = Counts::new();
    for h in 0..headers {
        c.restart();
        let header: [u8; 80] = SplitMix64::stream(seed, h).bytes();
        match (function, rounds) {
            (_, None) => {
                for i in 0..per {
                    let mut rng = SplitMix64::stream(seed ^ 0xc0_47_01, (h << 32) | i);
                    c.observe(rng.words());
                }
            }
            ("sha256-header-nonce", Some(r)) => {
                let mid = HeaderMidstate::with_rounds(&header, r);
                for nonce in 0..per as u32 {
                    c.observe(hash_number_words(&compress_words(&mid.state, &mid.second_block(nonce), r)));
                }
            }
            ("sha256d-header-nonce", Some(r)) => {
                let mid = HeaderMidstate::with_rounds(&header, r);
                for nonce in 0..per as u32 {
                    c.observe(hash_number_words(&mid.hash_words(nonce)));
                }
            }
            ("sha256d-random-inputs", Some(r)) => {
                for i in 0..per {
                    let mut rng = SplitMix64::stream(seed ^ 0x0a4d, (h << 32) | i);
                    let hd: [u8; 80] = rng.bytes();
                    c.observe(hash_number_words(&HeaderMidstate::with_rounds(&hd, r).hash_words(rng.next_u32())));
                }
            }
            (f, _) => anyhow::bail!("unknown function {f}"),
        }
    }
    Ok(c)
}

struct Series {
    p_bits: Vec<f64>,
    p_lz: Vec<f64>,
    p_agree: Vec<f64>,
    hit_ratio: Vec<f64>,
    digest_input: Vec<Vec<u64>>,
}

fn series(function: &str, rounds: Option<usize>, seed: u64, seeds: u64, headers: u64, per: u64) -> Result<Series> {
    let cells: Vec<Counts> = (0..seeds).into_par_iter().map(|s| cell(function, rounds, derived(seed, s), headers, per)).collect::<Result<_>>()?;
    let mut out = Series { p_bits: vec![], p_lz: vec![], p_agree: vec![], hit_ratio: vec![], digest_input: vec![] };
    for c in cells {
        let (a, b, d) = c.p_values();
        out.p_bits.push(a);
        out.p_lz.push(b);
        out.p_agree.push(d);
        out.hit_ratio.push(c.lz[8..].iter().sum::<u64>() as f64 / c.hashes() as f64 * 256.0);
        out.digest_input.push(c.ones.iter().chain(&c.lz).chain(&c.agree).copied().collect());
    }
    Ok(out)
}

fn summarize(s: &Series, threshold: f64) -> (Value, bool) {
    let mut tests = serde_json::Map::new();
    let mut deviation = false;
    for (name, ps) in [("bit_frequency", &s.p_bits), ("leading_zeros", &s.p_lz), ("consecutive_agreement", &s.p_agree)] {
        let (d, p) = ks_uniform(ps);
        let small = ps.iter().filter(|&&p| p < 0.01).count() as u64;
        deviation |= p < threshold;
        tests.insert(name.into(), json!({
            "ks_d": d, "ks_p": p,
            "seeds_with_p_below_0_01": small,
            "fraction_ci95": wilson(small, ps.len() as u64, Z95),
            "min_p": ps.iter().copied().fold(1.0, f64::min),
        }));
    }
    let (mean, ci) = mean_ci95(&s.hit_ratio);
    tests.insert("target_8bit_hit_ratio".into(), json!({ "mean": mean, "ci95": ci, "expected": 1.0 }));
    (Value::Object(tests), deviation)
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let functions: Vec<String> = params["functions"].as_array().context("functions")?.iter().filter_map(|f| f.as_str().map(str::to_string)).collect();
    let rounds = p_rounds(params)?;
    let seeds = p_u64(params, "seeds")?;
    let headers = p_u64(params, "headers_per_seed")?;
    let per = p_u64(params, "nonces_per_header")?;
    let alpha = p_f64(params, "alpha")?;
    let threshold = alpha / ((functions.len() * rounds.len() + 1) * 3) as f64;
    let (mut obs, mut det, mut flags) = (Vec::new(), Vec::new(), Vec::new());
    let control = series("control", None, seed, seeds, headers, per)?;
    let (control_summary, control_dev) = summarize(&control, threshold);
    det.push(json!({ "function": "control", "counts": control.digest_input }));
    for f in &functions {
        for &r in &rounds {
            let s = series(f, Some(r), seed, seeds, headers, per)?;
            let (summary, dev) = summarize(&s, threshold);
            flags.push((r, dev));
            det.push(json!({ "function": f, "rounds": r, "counts": s.digest_input }));
            obs.push(json!({ "function": f, "rounds": r, "seeds": seeds, "hashes_per_seed": headers * per, "tests": summary, "deviation_detected": dev }));
        }
    }
    let flagged: Vec<String> = obs.iter().filter(|o| o["deviation_detected"] == true).map(|o| format!("{}@{}", o["function"].as_str().unwrap_or(""), o["rounds"])).collect();
    let full: Vec<String> = obs.iter().filter(|o| o["rounds"] == FULL_ROUNDS).map(|o| {
        let t = &o["tests"]["target_8bit_hit_ratio"];
        format!("{} hit ratio {:.4} (95% CI {:.4}..{:.4})", o["function"].as_str().unwrap_or(""), t["mean"].as_f64().unwrap_or(0.0), t["ci95"][0].as_f64().unwrap_or(0.0), t["ci95"][1].as_f64().unwrap_or(0.0))
    }).collect();
    let summary = vec![
        format!("{seeds} independent seeds x {} hashes per cell; KS threshold {threshold:.2e}.", headers * per),
        format!("Negative control (non-SHA PRF) deviates: {control_dev} — {}", if control_dev { "the test battery is miscalibrated; results below are unreliable" } else { "battery calibrated at this size" }),
        format!("Cells with p-value distributions departing from uniform: {flagged:?}."),
        format!("Full-round 8-bit target hit ratios (observed/expected): {}.", full.join("; ")),
    ];
    Ok(Outcome::new(json!({ "control": { "tests": control_summary, "deviation_detected": control_dev }, "cells": obs }), json!(det), flags, summary))
}

/// The negative control must pass, and SHA-256 single/double paths are
/// recomputed from full inputs with the independent implementation.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let rounds = p_rounds(params)?;
    let ind = verification::independent::Sha256::default();
    let mut problems = Vec::new();
    if outcome.observations["control"]["deviation_detected"] != false {
        problems.push("negative control deviated: test battery miscalibrated".to_string());
    }
    for &r in &rounds {
        let mut header: [u8; 80] = SplitMix64::stream(derived(seed, 0), 0).bytes();
        let mid = HeaderMidstate::with_rounds(&header, r);
        for nonce in 0..256u32 {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let single = bitcoin_header::Target::from_hash(&ind.digest(&header, r)).words();
            let double = bitcoin_header::Target::from_hash(&ind.sha256d(&header, r)).words();
            if single != hash_number_words(&compress_words(&mid.state, &mid.second_block(nonce), r)) {
                problems.push(format!("single r{r} nonce {nonce}"));
            }
            if double != hash_number_words(&mid.hash_words(nonce)) {
                problems.push(format!("double r{r} nonce {nonce}"));
            }
        }
    }
    problems.truncate(10);
    Ok(Verification {
        method: "SHA-256 and SHA-256d header paths recomputed over the full 80-byte header with the independent implementation (256 nonces per round count)".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "all recomputed hashes identical".into() } else { problems.join("; ") },
    })
}
