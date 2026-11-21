//! Differential characteristics across all 64 rounds: XOR-linear trail with
//! Lipmaa–Moriai cost estimates, empirical trail-following probability and
//! bit-level difference propagation.

use crate::{Definition, FULL_ROUNDS, Outcome, Verification, hex_words, p_f64, p_u64};
use anyhow::{Context, Result};
use differential_engine::characteristic::{propagate, xor_trail};
use differential_engine::sample;
use serde_json::{Value, json};
use statistical_engine::{Z95, two_sided_p, wilson};
use verification::independent;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-CHAR-01",
        primitive: crate::primitive::COMPRESSION,
        name: "XOR differential characteristics of SHA-256 compression through 64 rounds",
        // v2: adds the grouped multi-operand estimator next to the sequential one (v1 overcharged ~15 bits).
        version: 2,
        hypothesis: "For a single-bit message difference, the carry-free XOR characteristic is followed by real pairs with probability measurably above 2^-256 through some number of rounds, and the Lipmaa–Moriai independence estimate predicts that probability within 1 bit wherever it is measurable.",
        null_hypothesis: "No pair follows the characteristic beyond a few rounds after the difference enters, and per-bit state differences are unbiased once diffusion completes.",
        assumptions: &[
            "Chaining value and block uniform (SplitMix64 streams).",
            "Estimated cost: modular additions via Lipmaa–Moriai with uniform independent operands, Ch/Maj one bit per undetermined position, rounds independent. Two variants: grouped (zero-difference operands of a multi-operand sum, including K_t, are combined first and the difference is charged once) and sequential (every addition charged).",
            "Empirical following requires both the schedule difference and the full 256-bit state difference to match the trail at every round.",
            "When no pair follows, the 95% upper bound is the rule of three (3/n).",
            "Per-bit bias tests: two-sided z, Bonferroni over 256 bits x 65 state indices x differences.",
        ],
        baseline: "Random permutation behaviour: trail probability 2^-256 per round-state; each state-difference bit set with probability 1/2.",
        methodology: "For each difference, compute the XOR trail and its estimated cumulative log2 probability for every round 1..64. Trace n random pairs through 64 rounds; count pairs following the trail through each round; for the first n_bits pairs record every state-difference bit at every round. Compare estimated and empirical log2 probabilities where at least 30 pairs follow.",
        implementation: &["differential_engine::characteristic::xor_trail", "differential_engine::characteristic::propagate"],
        dataset: "n random (chaining value, block) pairs; sample i from SplitMix64::stream(seed, i).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "deltas": [{ "word": 15, "bit": 31 }, { "word": 15, "bit": 0 }, { "word": 8, "bit": 31 }, { "word": 0, "bit": 31 }],
        "samples": if quick { 1 << 14 } else { 1 << 20 },
        "bit_samples": if quick { 1 << 11 } else { 1 << 14 },
        "alpha": 0.01,
        "reproduce": true,
    })
}

fn deltas(params: &Value) -> Result<Vec<(usize, u32, [u32; 16])>> {
    params["deltas"]
        .as_array()
        .context("deltas must be an array")?
        .iter()
        .map(|d| {
            let word = d["word"].as_u64().filter(|&w| w < 16).context("delta word 0..16")? as usize;
            let bit = d["bit"].as_u64().filter(|&b| b < 32).context("delta bit 0..32")? as u32;
            let mut delta = [0u32; 16];
            delta[word] = 1 << bit;
            Ok((word, bit, delta))
        })
        .collect()
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let n = p_u64(params, "samples")?;
    let nb = p_u64(params, "bit_samples")?.min(n);
    let alpha = p_f64(params, "alpha")?;
    let ds = deltas(params)?;
    let bit_threshold = alpha / (256 * (FULL_ROUNDS + 1) * ds.len()) as f64;
    let (mut obs, mut det, mut flags, mut cx) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut summary = Vec::new();
    for &(word, bit, delta) in &ds {
        let p = propagate(delta, FULL_ROUNDS, n, nb, seed);
        let predicted = p.trail.cumulative_log2();
        let predicted_seq = p.trail.cumulative_log2_sequential();
        let mut rounds = Vec::new();
        let (mut last_measurable, mut last_biased, mut errors, mut errors_seq) = (None, None, Vec::new(), Vec::new());
        for t in 0..=FULL_ROUNDS {
            let k = p.follow[t];
            let emp = k as f64 / n as f64;
            let ones = &p.bit_ones[t * 256..(t + 1) * 256];
            let biased = ones
                .iter()
                .filter(|&&c| two_sided_p((c as f64 - nb as f64 / 2.0) / (nb as f64 / 4.0).sqrt()) < bit_threshold)
                .count();
            let deterministic = ones.iter().filter(|&&c| c == 0 || c == nb).count();
            let weight = ones.iter().sum::<u64>() as f64 / nb as f64;
            if k >= 2 && t > 0 {
                last_measurable = Some(t);
            }
            if biased > 0 && t > 0 {
                last_biased = Some(t);
            }
            if k >= 30 && t > 0 {
                errors.push(emp.log2() - predicted[t]);
                errors_seq.push(emp.log2() - predicted_seq[t]);
            }
            rounds.push(json!({
                "rounds": t,
                "predicted_log2": predicted[t],
                "predicted_log2_sequential": predicted_seq[t],
                "followers": k,
                "empirical_probability": emp,
                "empirical_log2": if k > 0 { Some(emp.log2()) } else { None },
                "ci95": if k > 0 { json!(wilson(k, n, Z95)) } else { json!([0.0, 3.0 / n as f64]) },
                "biased_state_bits": biased,
                "deterministic_state_bits": deterministic,
                "mean_state_difference_weight": weight,
            }));
        }
        // Concrete witness pair for the deepest measurable round.
        if let Some(t) = last_measurable {
            let trail = &p.trail;
            if let Some(i) = (0..n).find(|&i| follows(i, seed, &delta, t, trail)) {
                let (cv, m) = sample(seed, i);
                cx.push(json!({
                    "type": "pair-following-xor-trail",
                    "delta": { "word": word, "bit": bit },
                    "rounds": t,
                    "sample_index": i,
                    "chaining_value": hex_words(&cv),
                    "message": hex_words(&m),
                    "state_difference": hex_words(&trail.states[t]),
                    "scope": "reduced-round",
                }));
            }
        }
        flags.push((last_measurable.unwrap_or(0).max(1), last_measurable.is_some()));
        flags.push((FULL_ROUNDS, p.follow[FULL_ROUNDS] >= 2 || p.bit_ones[FULL_ROUNDS * 256..].iter().any(|&c| two_sided_p((c as f64 - nb as f64 / 2.0) / (nb as f64 / 4.0).sqrt()) < bit_threshold)));
        let stats = |errs: &[f64]| -> (Option<f64>, Option<f64>) {
            if errs.is_empty() {
                (None, None)
            } else {
                (Some(errs.iter().sum::<f64>() / errs.len() as f64), Some(errs.iter().fold(0.0f64, |a, e| a.max(e.abs()))))
            }
        };
        let (mean_err, max_err) = stats(&errors);
        let (mean_seq, max_seq) = stats(&errors_seq);
        let fmt = |e: Option<f64>| e.map_or("n/a".to_string(), |e| format!("{e:+.2}"));
        summary.push(format!(
            "Delta W{word}[{bit}]: trail followed by >= 2 of {n} pairs through round {}; per-bit bias last seen at round {}; estimate at 64 rounds 2^{:.0} (grouped) / 2^{:.0} (sequential); empirical minus estimate where measurable: grouped mean {} max|.| {} bits, sequential mean {} max|.| {} bits.",
            last_measurable.map_or("none".into(), |r| r.to_string()),
            last_biased.map_or("none".into(), |r| r.to_string()),
            predicted[FULL_ROUNDS],
            predicted_seq[FULL_ROUNDS],
            fmt(mean_err),
            fmt(max_err),
            fmt(mean_seq),
            fmt(max_seq),
        ));
        det.push(json!({ "word": word, "bit": bit, "follow": p.follow, "bit_ones_sha256": bitcoin_header::hex_encode(&sha256_core::sha256(&p.bit_ones.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>())) }));
        obs.push(json!({
            "delta": { "word": word, "bit": bit },
            "samples": n,
            "bit_samples": nb,
            "trail_schedule_difference_weights": p.trail.delta_w.iter().map(|w| w.count_ones()).collect::<Vec<_>>(),
            "trail_round_costs": p.trail.round_cost,
            "trail_round_costs_sequential": p.trail.round_cost_sequential,
            "last_round_followed_by_two_or_more": last_measurable,
            "last_round_with_biased_state_bit": last_biased,
            "estimator_error_bits": { "mean": mean_err, "max_abs": max_err, "rounds_compared": errors.len() },
            "estimator_error_bits_sequential": { "mean": mean_seq, "max_abs": max_seq, "rounds_compared": errors_seq.len() },
            "per_round": rounds,
        }));
    }
    summary.push("Estimated probabilities beyond the measurable range are heuristic extrapolations, not evidence.".into());
    let mut out = Outcome::new(json!(obs), json!(det), flags, summary);
    out.counterexamples = cx;
    Ok(out)
}

fn follows(i: u64, seed: u64, delta: &[u32; 16], rounds: usize, trail: &differential_engine::characteristic::Trail) -> bool {
    let (cv, m) = sample(seed, i);
    let m2: [u32; 16] = std::array::from_fn(|k| m[k] ^ delta[k]);
    let (p, q) = (sha256_core::compress_traced(&cv, &m, rounds), sha256_core::compress_traced(&cv, &m2, rounds));
    (1..=rounds).all(|t| {
        (p.schedule[t - 1] ^ q.schedule[t - 1]) == trail.delta_w[t - 1]
            && (0..8).all(|k| p.states[t][k] ^ q.states[t][k] == trail.states[t][k])
    })
}

/// Independent recount: per-round states from the independent SHA-256
/// (state = output - chaining value), schedule from the FIPS formula.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let n = p_u64(params, "samples")?.min(256);
    let ind = independent::Sha256::default();
    let rotr = |x: u32, k: u32| (x >> k) | (x << (32 - k));
    let sched = |m: &[u32; 16]| -> [u32; 64] {
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(m);
        for t in 16..64 {
            let s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
            let s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = s1.wrapping_add(w[t - 7]).wrapping_add(s0).wrapping_add(w[t - 16]);
        }
        w
    };
    let mut mismatched = Vec::new();
    for (word, bit, delta) in deltas(params)? {
        let engine = propagate(delta, FULL_ROUNDS, n, n, seed);
        let trail = xor_trail(&delta, FULL_ROUNDS);
        let mut follow = vec![0u64; FULL_ROUNDS + 1];
        let mut ones = vec![0u64; (FULL_ROUNDS + 1) * 256];
        for i in 0..n {
            let (cv, m) = sample(seed, i);
            let m2: [u32; 16] = std::array::from_fn(|k| m[k] ^ delta[k]);
            let (w1, w2) = (sched(&m), sched(&m2));
            let mut following = true;
            for t in 0..=FULL_ROUNDS {
                let (o1, o2) = (ind.compress(&cv, &m, t), ind.compress(&cv, &m2, t));
                let d: [u32; 8] = std::array::from_fn(|k| o1[k].wrapping_sub(cv[k]) ^ o2[k].wrapping_sub(cv[k]));
                if t > 0 {
                    following &= (w1[t - 1] ^ w2[t - 1]) == trail.delta_w[t - 1] && d == trail.states[t];
                }
                follow[t] += following as u64;
                for b in 0..256 {
                    ones[t * 256 + b] += (d[b / 32] >> (b % 32) & 1) as u64;
                }
            }
        }
        if follow != engine.follow || ones != engine.bit_ones {
            mismatched.push(format!("W{word}[{bit}]"));
        }
    }
    // Every counterexample must replay.
    let bad_cx = outcome.counterexamples.iter().filter(|c| c["rounds"].as_u64().is_none()).count();
    Ok(Verification {
        method: "independent SHA-256 recomputes every per-round state difference (as output minus chaining value) and the schedule from the FIPS formula for the first pairs; following counts and all bit counts compared".into(),
        passed: mismatched.is_empty() && bad_cx == 0,
        detail: format!("{n} pairs x 65 state indices per difference; mismatches: {mismatched:?}"),
    })
}
