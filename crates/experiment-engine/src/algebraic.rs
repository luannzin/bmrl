//! Algebraic structure over GF(2): carry contribution per round (real vs
//! carry-free compression) and algebraic degree in chosen message bits
//! (proved upper bounds vs empirical cube sums).

use crate::{Definition, FULL_ROUNDS, Outcome, Verification, hex_words, p_f64, p_u64};
use algebraic_engine::{DegreeModel, compress_carry_free, cube_sum};
use anyhow::{Context, Result};
use differential_engine::sample;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::compress_words;
use statistical_engine::{binomial_z, mean_ci95, two_sided_p};
use verification::independent;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-ALG-01",
        primitive: crate::primitive::COMPRESSION,
        name: "GF(2) algebraic degree and carry contribution of SHA-256 compression",
        version: 1,
        hypothesis: "Viewed over GF(2) with carries modelled exactly, r-round SHA-256 compression has output bits of algebraic degree below d in a set of d message bits (zero cube sums), and agrees with its carry-free (XOR) model on more than half of the output bits, for r up to some bound.",
        null_hypothesis: "Cube sums of output bits are uniform (an output bit sums to zero over all K base points with probability 2^-K) and agreement with the carry-free model is 1/2 per bit.",
        assumptions: &[
            "Cubes are d consecutive bits (lowest or highest) of one message word; other message bits and the chaining value are uniform per base point.",
            "Degree upper bounds propagate exact ripple-carry formulas: s_i = a_i^b_i^c_{i-1}, c_i = maj(a_i, b_i, c_{i-1}); constants have degree 0.",
            "A bit with degree bound < d must have a zero cube sum; a violation would be a bug and fails verification.",
            "Zero-sum counts are flagged only above the Binomial(256, 2^-K) tail at alpha / configurations.",
            "Carry-free agreement: bits treated as independent Bernoulli(1/2) under the null (normal approximation).",
        ],
        baseline: "Random function: each cube-sum bit uniform; agreement with any fixed function 1/2.",
        methodology: "For each cube (word, position, dimension d) and round count, compute the proven degree bound of every output bit and the cube sum (XOR over 2^d inputs) at K random base points; count bits that are zero at every base point. Separately, compare r-round compression with its carry-free model on random inputs.",
        implementation: &["algebraic_engine::DegreeModel", "algebraic_engine::cube_sum", "algebraic_engine::compress_carry_free"],
        dataset: "K base points (chaining value, block) from SplitMix64::stream(seed, k); carry comparison on n further samples.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "cube_words": [15, 0],
        "cube_positions": ["low", "high"],
        "dimensions": if quick { json!([4, 8]) } else { json!([4, 8, 12, 16]) },
        "rounds_after_entry": 8,
        "base_points": if quick { 8 } else { 16 },
        "carry_samples": if quick { 512 } else { 4096 },
        "carry_rounds": [1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 64],
        "alpha": 0.01,
        "reproduce": true,
    })
}

#[derive(Clone)]
struct Cube {
    word: usize,
    high: bool,
    bits: Vec<usize>,
    rounds: usize,
}

fn cubes(params: &Value) -> Result<Vec<Cube>> {
    let span = p_u64(params, "rounds_after_entry")? as usize;
    let dims: Vec<usize> = params["dimensions"].as_array().context("dimensions")?.iter().filter_map(|d| d.as_u64()).map(|d| d as usize).collect();
    anyhow::ensure!(dims.iter().all(|&d| (1..=20).contains(&d)), "dimensions must be 1..=20");
    let mut out = Vec::new();
    for w in params["cube_words"].as_array().context("cube_words")?.iter().filter_map(Value::as_u64) {
        let w = w as usize;
        anyhow::ensure!(w < 16, "cube word must be < 16");
        for pos in params["cube_positions"].as_array().context("cube_positions")?.iter().filter_map(Value::as_str) {
            let high = pos == "high";
            for &d in &dims {
                let bits: Vec<usize> = if high { (32 - d..32).map(|b| w * 32 + b).collect() } else { (0..d).map(|b| w * 32 + b).collect() };
                let mut rounds: Vec<usize> = (w + 1..=(w + span).min(FULL_ROUNDS)).collect();
                if !rounds.contains(&FULL_ROUNDS) {
                    rounds.push(FULL_ROUNDS);
                }
                out.extend(rounds.into_iter().map(|r| Cube { word: w, high, bits: bits.clone(), rounds: r }));
            }
        }
    }
    Ok(out)
}

/// Smallest c with P(Binomial(256, 2^-k) > c) < alpha.
fn zero_sum_threshold(k: u32, alpha: f64) -> u32 {
    let p = 0.5f64.powi(k as i32);
    let mut pmf = (1.0 - p).powi(256);
    let mut tail = 1.0 - pmf;
    let mut c = 0u32;
    while tail >= alpha && c < 256 {
        pmf *= (256 - c) as f64 / (c + 1) as f64 * p / (1.0 - p);
        tail -= pmf;
        c += 1;
    }
    c
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let k = p_u64(params, "base_points")?;
    let alpha = p_f64(params, "alpha")?;
    let cs = cubes(params)?;
    let carry_rounds: Vec<usize> = params["carry_rounds"].as_array().context("carry_rounds")?.iter().filter_map(Value::as_u64).map(|r| r as usize).collect();
    let alpha_cfg = alpha / (cs.len() + carry_rounds.len()) as f64;
    let threshold = zero_sum_threshold(k as u32, alpha_cfg);
    let (mut obs, mut det, mut flags, mut cx) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut violations = 0u64;
    for c in &cs {
        let d = c.bits.len();
        let bounds = DegreeModel::compression(&c.bits, c.rounds);
        let guaranteed: Vec<usize> = (0..256).filter(|&b| bounds[b / 32][b % 32] < d as u16).collect();
        let sums: Vec<[u32; 8]> = (0..k).into_par_iter().map(|i| {
            let (cv, m) = sample(seed, i);
            cube_sum(&cv, &m, &c.bits, c.rounds)
        }).collect();
        let or_all = sums.iter().fold([0u32; 8], |acc, s| std::array::from_fn(|w| acc[w] | s[w]));
        let zero_bits: Vec<usize> = (0..256).filter(|&b| or_all[b / 32] >> (b % 32) & 1 == 0).collect();
        let v = guaranteed.iter().filter(|b| !zero_bits.contains(b)).count() as u64;
        violations += v;
        let deviation = zero_bits.len() as u32 > threshold;
        flags.push((c.rounds, deviation));
        let max_bound = bounds.iter().flat_map(|w| w.iter()).copied().max().unwrap_or(0);
        if deviation && c.rounds < FULL_ROUNDS {
            cx.push(json!({
                "type": "zero-sum-cube",
                "cube_message_bits": c.bits,
                "rounds": c.rounds,
                "zero_sum_output_bits": zero_bits.iter().take(32).collect::<Vec<_>>(),
                "zero_sum_output_bit_count": zero_bits.len(),
                "base_points_checked": k,
                "first_base_point_cube_sum": hex_words(&sums[0]),
                "scope": "reduced-round",
            }));
        }
        det.push(json!({ "word": c.word, "high": c.high, "d": d, "rounds": c.rounds, "sums": sums.iter().map(|s| hex_words(s)).collect::<Vec<_>>() }));
        obs.push(json!({
            "cube": { "word": c.word, "position": if c.high { "high" } else { "low" }, "dimension": d },
            "rounds": c.rounds,
            "rounds_since_entry": c.rounds - c.word,
            "degree_bound_max": max_bound,
            "bits_with_degree_bound_below_d": guaranteed.len(),
            "zero_sum_bits_observed": zero_bits.len(),
            "zero_sum_threshold": threshold,
            "bound_violations": v,
            "deviation_detected": deviation,
        }));
    }
    let n = p_u64(params, "carry_samples")?;
    let mut carry = Vec::new();
    for &r in &carry_rounds {
        let agree: Vec<f64> = (0..n).into_par_iter().map(|i| {
            let (cv, m) = sample(seed ^ 0xca22, i);
            let (a, b) = (compress_words(&cv, &m, r), compress_carry_free(&cv, &m, r));
            (256 - a.iter().zip(&b).map(|(x, y)| (x ^ y).count_ones()).sum::<u32>()) as f64 / 256.0
        }).collect();
        let total: u64 = agree.iter().map(|f| (f * 256.0).round() as u64).sum();
        let z = binomial_z(total, n * 256, 0.5);
        let (mean, ci) = mean_ci95(&agree);
        let deviation = two_sided_p(z) < alpha_cfg;
        flags.push((r, deviation));
        det.push(json!({ "carry_rounds": r, "agreeing_bits": total }));
        carry.push(json!({ "rounds": r, "mean_agreement": mean, "ci95": ci, "z": z, "deviation_detected": deviation }));
    }
    let last_zero_sum = |word: usize| obs.iter().filter(|o| o["cube"]["word"] == word && o["deviation_detected"] == true).filter_map(|o| o["rounds_since_entry"].as_u64()).max();
    let mut summary = Vec::new();
    for w in cs.iter().map(|c| c.word).collect::<std::collections::BTreeSet<_>>() {
        summary.push(format!(
            "Cubes in W{w}: zero-sum distinguishers up to {} rounds after the word enters (round {w}).",
            last_zero_sum(w).map_or("no".into(), |r| r.to_string())
        ));
    }
    let last_carry = carry.iter().filter(|c| c["deviation_detected"] == true).filter_map(|c| c["rounds"].as_u64()).max();
    summary.push(format!("Carry-free model agrees with the real function beyond chance up to {} rounds.", last_carry.map_or("no".into(), |r| r.to_string())));
    summary.push(format!("Degree-bound violations (must be 0): {violations}."));
    let mut out = Outcome::new(json!({ "cubes": obs, "carry_free_agreement": carry, "degree_bound_violations": violations }), json!(det), flags, summary);
    out.counterexamples = cx;
    Ok(out)
}

/// Independent recomputation of cube sums (d <= 8, first two base points)
/// and the requirement that proven degree bounds are never violated.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let ind = independent::Sha256::default();
    let mut mismatched = 0;
    let mut checked = 0;
    for c in cubes(params)?.iter().filter(|c| c.bits.len() <= 8) {
        for i in 0..2u64.min(p_u64(params, "base_points")?) {
            let (cv, mut m) = sample(seed, i);
            for &j in &c.bits {
                m[j / 32] &= !(1 << (j % 32));
            }
            let mut acc = [0u32; 8];
            for x in 0u32..1 << c.bits.len() {
                let mut mm = m;
                for (k, &j) in c.bits.iter().enumerate() {
                    mm[j / 32] |= (x >> k & 1) << (j % 32);
                }
                let o = ind.compress(&cv, &mm, c.rounds);
                acc.iter_mut().zip(o).for_each(|(a, b)| *a ^= b);
            }
            let (cv0, m0) = sample(seed, i);
            checked += 1;
            if acc != cube_sum(&cv0, &m0, &c.bits, c.rounds) {
                mismatched += 1;
            }
        }
    }
    let violations = outcome.observations["degree_bound_violations"].as_u64().unwrap_or(u64::MAX);
    Ok(Verification {
        method: "independent SHA-256 recomputes cube sums (d <= 8, two base points per configuration); proven degree bounds must never be contradicted by observed cube sums".into(),
        passed: mismatched == 0 && violations == 0,
        detail: format!("{checked} cube sums recomputed, {mismatched} mismatches; degree-bound violations {violations}"),
    })
}
