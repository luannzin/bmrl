//! XOR-differential experiment: for single-bit message differences, how many
//! rounds after the difference enters does a high-probability output
//! difference survive?

use crate::{Definition, FULL_ROUNDS, Outcome, Verification, hex_words, p_f64, p_u64};
use anyhow::{Context, Result};
use differential_engine::{OUT_BITS, analyze_differential, differential, sample};
use serde_json::{Value, json};
use std::collections::HashMap;
use verification::independent;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-DIFF-01",
        primitive: crate::primitive::COMPRESSION,
        name: "Single-bit XOR differentials through reduced-round SHA-256 compression",
        version: 1,
        hypothesis: "For a single-bit difference in message word W[i], some output difference of the r-round compression function occurs with probability far above 2^-256 for r up to some bound beyond the round where W[i] enters (round i).",
        null_hypothesis: "Output differences are uniformly distributed: among n samples no output difference repeats (probability about n^2 / 2^257) and output-difference weight follows Binomial(256, 1/2).",
        assumptions: &[
            "Chaining value and message block uniform (SplitMix64 streams); the same samples are used for all configurations.",
            "A repeated 256-bit output difference among n << 2^128 samples is evidence of a non-random differential, not chance.",
            "Weight chi-square with Bonferroni correction over all configurations.",
            "XOR differences only; modular-difference characteristics are out of scope for version 1.",
        ],
        baseline: "Random function: no repeated output difference among n samples; weight ~ Binomial(256, 1/2).",
        methodology: "For each difference and round count, compress n random (cv, M) and (cv, M xor delta) with tracing; record the full 256-bit output difference, its weight, and the state-difference weight after every round. Report the most frequent differences with Wilson 95% intervals. Round counts start one round after the difference enters and always include 64.",
        implementation: &["differential_engine::differential", "differential_engine::analyze_differential", "sha256_core::compress_traced"],
        dataset: "n random (chaining value, message block) pairs; sample i from SplitMix64::stream(seed, i).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "deltas": [{ "word": 15, "bit": 31 }, { "word": 15, "bit": 0 }, { "word": 0, "bit": 31 }],
        "rounds_after_entry": 8,
        "samples": if quick { 4096 } else { 131072 },
        "alpha": 0.01,
        "top_k": 3,
        "reproduce": true,
    })
}

struct Config {
    word: usize,
    bit: u32,
    delta: [u32; 16],
    rounds: usize,
}

fn configs(params: &Value) -> Result<Vec<Config>> {
    let span = p_u64(params, "rounds_after_entry")? as usize;
    let mut out = Vec::new();
    for d in params["deltas"].as_array().context("deltas must be an array")? {
        let word = d["word"].as_u64().filter(|&w| w < 16).context("delta word must be 0..16")? as usize;
        let bit = d["bit"].as_u64().filter(|&b| b < 32).context("delta bit must be 0..32")? as u32;
        let mut delta = [0u32; 16];
        delta[word] = 1 << bit;
        let mut rounds: Vec<usize> = (word + 1..=(word + span).min(FULL_ROUNDS)).collect();
        if !rounds.contains(&FULL_ROUNDS) {
            rounds.push(FULL_ROUNDS);
        }
        out.extend(rounds.into_iter().map(|rounds| Config { word, bit, delta, rounds }));
    }
    Ok(out)
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let samples = p_u64(params, "samples")?;
    let top_k = p_u64(params, "top_k")? as usize;
    let configs = configs(params)?;
    let alpha_cfg = p_f64(params, "alpha")? / configs.len() as f64;
    let (mut obs, mut det, mut flags) = (Vec::new(), Vec::new(), Vec::new());
    let mut last_hit: HashMap<(usize, u32), usize> = HashMap::new();
    for c in &configs {
        let d = differential(c.rounds, c.delta, samples, seed, top_k);
        let s = analyze_differential(&d, alpha_cfg);
        flags.push((c.rounds, s.distinguishable));
        if s.top_count >= 2 {
            let e = last_hit.entry((c.word, c.bit)).or_insert(0);
            *e = (*e).max(c.rounds);
        }
        let top: Vec<Value> = d
            .top
            .iter()
            .filter(|(_, n)| *n >= 2)
            .map(|(diff, n)| {
                let p = *n as f64 / samples as f64;
                json!({
                    "difference": hex_words(diff),
                    "weight": diff.iter().map(|w| w.count_ones()).sum::<u32>(),
                    "count": n,
                    "probability": p,
                    "log2_probability": p.log2(),
                    "ci95": statistical_engine::wilson(*n, samples, statistical_engine::Z95),
                })
            })
            .collect();
        det.push(json!({
            "word": c.word, "bit": c.bit, "rounds": c.rounds,
            "distinct": d.distinct,
            "top": d.top.iter().map(|(diff, n)| json!([hex_words(diff), n])).collect::<Vec<_>>(),
            "weight_hist": d.weight_hist,
        }));
        obs.push(json!({
            "delta": { "word": c.word, "bit": c.bit },
            "rounds": c.rounds,
            "rounds_since_entry": c.rounds - c.word,
            "samples": samples,
            "distinct_output_differences": d.distinct,
            "repeated_differences": top,
            "mean_output_weight": s.mean_output_weight,
            "mean_state_weight_per_round": s.mean_state_weight_per_round,
            "weight_chi_square": { "statistic": s.weight_gof.statistic, "df": s.weight_gof.df, "p_value": s.weight_gof.p_value },
            "alpha_per_configuration": alpha_cfg,
            "deviation_detected": s.distinguishable,
        }));
    }
    let mut summary = Vec::new();
    for c in configs.iter().filter(|c| c.rounds == FULL_ROUNDS) {
        match last_hit.get(&(c.word, c.bit)) {
            Some(r) => summary.push(format!(
                "Delta W{}[{}]: repeated output differences observed up to {r} rounds ({} rounds after entry).",
                c.word,
                c.bit,
                r - c.word
            )),
            None => summary.push(format!("Delta W{}[{}]: no repeated output difference in any tested round count.", c.word, c.bit)),
        }
    }
    summary.push(format!(
        "With n = {samples}, differentials with probability below about 2^{:.1} cannot be observed, so absence of repeats does not exclude lower-probability characteristics.",
        -(samples as f64).log2() + 1.0
    ));
    Ok(Outcome::new(json!(obs), json!(det), flags, summary))
}

/// Recompute the first 256 samples of every configuration with the independent SHA-256.
pub fn verify(params: &Value, seed: u64) -> Result<Verification> {
    let n = p_u64(params, "samples")?.min(256);
    let ind = independent::Sha256::default();
    let mut mismatched = Vec::new();
    let configs = configs(params)?;
    for c in &configs {
        let engine = differential(c.rounds, c.delta, n, seed, usize::MAX);
        let mut counts: HashMap<[u32; 8], u64> = HashMap::new();
        let mut hist = vec![0u64; OUT_BITS + 1];
        for i in 0..n {
            let (cv, m) = sample(seed, i);
            let m2: [u32; 16] = std::array::from_fn(|k| m[k] ^ c.delta[k]);
            let (a, b) = (ind.compress(&cv, &m, c.rounds), ind.compress(&cv, &m2, c.rounds));
            let d: [u32; 8] = std::array::from_fn(|k| a[k] ^ b[k]);
            hist[d.iter().map(|w| w.count_ones() as usize).sum::<usize>()] += 1;
            *counts.entry(d).or_insert(0) += 1;
        }
        let mut engine_counts: Vec<_> = engine.top.clone();
        engine_counts.sort();
        let mut ind_counts: Vec<_> = counts.into_iter().collect();
        ind_counts.sort();
        if engine_counts != ind_counts || engine.weight_hist != hist {
            mismatched.push(format!("W{}[{}]@{}", c.word, c.bit, c.rounds));
        }
    }
    Ok(Verification {
        method: "independent SHA-256 recomputes every output difference (full multiset) and weight histogram for the first samples of every configuration".into(),
        passed: mismatched.is_empty(),
        detail: format!("{n} samples x {} configurations; mismatches: {mismatched:?}", configs.len()),
    })
}
