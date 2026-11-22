//! Solver-found XOR characteristics of the second header block, measured on
//! real pairs, and exact proofs of the reduced-round header identities.
//!
//! The solver (`research/differential-cryptanalysis/trail_sat.py`, z3) finds
//! the minimum-weight characteristic under the signed carry-free model for
//! each number of rounds after the difference enters, over every difference
//! in the words a miner controls. Nothing here trusts the model: every round
//! of every returned characteristic is measured as a one-round transition on
//! uniform states (up to 2^33 samples), and short characteristics end to end
//! on header-structured pairs. The same script proves two identities over all
//! templates; they are re-checked numerically with the independent SHA-256.

use crate::smt::{run_script, z3_version};
use crate::{Definition, Outcome, Verification, ci_json, p_u64};
use anyhow::Result;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::{IV, K, State, big_sigma1, ch, round};
use statistical_engine::SplitMix64;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-SAT-01",
        primitive: crate::primitive::COMPRESSION,
        name: "Solver-optimal XOR characteristics from miner-controlled header words, measured",
        version: 1,
        hypothesis: "An optimal XOR characteristic found by a SAT solver over all differences in the nonce (or the nonce and time words) follows the second header block beyond round 5 with probability at least 2^-32, so that one template's nonce space contains a conforming pair.",
        null_hypothesis: "Every solver-optimal characteristic costs more than 32 bits once it covers round 5 of the second block, and the measured transitions are no more likely than the model says.",
        assumptions: &[
            "Model: signed carry-free sums with at most two digits per bit (cancellation allowed), free Ch/Maj choices where undetermined, round independence. It is an estimate; the measurements decide.",
            "Only rounds below 16 are searched, so the schedule words W16+ never enter; W2 (bits) and the padding never differ.",
            "W0 (the merkle root's last 4 bytes) never differs: the root's other 28 bytes are in block 1, so a W0 difference under one midstate needs a 224-bit merkle-root collision. Free words are W3 (nonce) and, for time-nonce, W1 (time). Time differences are not restricted to the consensus-valid window (about 2^13 s around the median of past blocks), so the time-nonce start is optimistic for the miner.",
            "A one-round transition is measured on uniform states with the characteristic's input differences: the Markov assumption made explicit. End-to-end following is measured on header-structured pairs where the weight allows.",
            "A solver timeout is reported as a lower bound on the weight, never as an optimum.",
        ],
        baseline: "One template offers 2^31 nonce pairs per difference: a characteristic below 2^-32 is followed by no pair in expectation.",
        methodology: "For each start and each number of rounds after entry R = 1.., the solver tightens a pseudo-Boolean weight bound from the previous optimum until the first satisfiable bound (the optimum) or a timeout. Each round of the result is measured with min(2^33, 2^(cost + 10)) samples. Identities are proved by asking z3 for a counterexample.",
        implementation: &["research/differential-cryptanalysis/trail_sat.py (z3)", "experiment_engine::trail_sat"],
        dataset: "One-round samples: SplitMix64::stream(seed ^ round tag, chunk); end-to-end pairs: SplitMix64::stream(seed ^ 0xe2e, i).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "starts": ["nonce", "time-nonce"],
        "max_rounds_after_entry": if quick { 2 } else { 5 },
        "timeout_ms": if quick { 60_000 } else { 600_000 },
        "budget_ms": if quick { 120_000 } else { 2_400_000 },
        "round_samples_max_log2": if quick { 22 } else { 33 },
        "end_to_end_samples_log2": if quick { 18 } else { 28 },
        "reproduce": false,
    })
}

/// Pairs (uniform state, W) whose one-round output differences in a and e match.
fn measure_round(din: State, dw: u32, dout: (u32, u32), t: usize, samples: u64, seed: u64) -> u64 {
    const CHUNK: u64 = 1 << 16;
    (0..samples.div_ceil(CHUNK))
        .into_par_iter()
        .map(|c| {
            let mut rng = SplitMix64::stream(seed ^ (t as u64) << 48, c);
            let mut k = 0;
            for _ in 0..CHUNK.min(samples - c * CHUNK) {
                let s: State = rng.words();
                let w = rng.next_u32();
                let s2: State = std::array::from_fn(|i| s[i] ^ din[i]);
                let (p, q) = (round(&s, K[t], w), round(&s2, K[t], w ^ dw));
                k += ((p[0] ^ q[0], p[4] ^ q[4]) == dout) as u64;
            }
            k
        })
        .sum()
}

/// Header-structured pairs following every round of the characteristic.
fn measure_end_to_end(dws: &[(usize, u32)], states: &[(u32, u32)], entry: usize, samples: u64, seed: u64) -> u64 {
    let last = entry + states.len();
    (0..samples)
        .into_par_iter()
        .filter(|&i| {
            let mut rng = SplitMix64::stream(seed ^ 0xe2e, i);
            let cv: State = rng.words();
            let mut w = [0u32; 16];
            w[..4].copy_from_slice(&rng.words::<4>());
            w[4] = 0x8000_0000;
            w[15] = 640;
            let mut w2 = w;
            for &(t, d) in dws {
                w2[t] ^= d;
            }
            let (mut s, mut s2) = (cv, cv);
            for t in 0..last {
                s = round(&s, K[t], w[t]);
                s2 = round(&s2, K[t], w2[t]);
                if t >= entry && (s[0] ^ s2[0], s[4] ^ s2[4]) != states[t - entry] {
                    return false;
                }
            }
            true
        })
        .count() as u64
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let Some(z3) = z3_version() else {
        return Ok(Outcome::skipped("z3 not available (pip install z3-solver)".into()));
    };
    let max_r = p_u64(params, "max_rounds_after_entry")?;
    let timeout = p_u64(params, "timeout_ms")?;
    let budget = p_u64(params, "budget_ms")?;
    let round_max = p_u64(params, "round_samples_max_log2")?.min(40) as u32;
    let e2e = 1u64 << p_u64(params, "end_to_end_samples_log2")?.min(40);
    let starts: Vec<String> = params["starts"].as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
    let identities = run_script("differential-cryptanalysis/trail_sat.py", &json!({ "mode": "identities", "timeout_ms": timeout }))?;

    let (mut obs, mut flags, mut summary, mut counterexamples) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for start in &starts {
        let res = run_script("differential-cryptanalysis/trail_sat.py", &json!({ "mode": "characteristics", "start": start, "max_rounds_after_entry": max_r, "timeout_ms": timeout, "budget_ms": budget, "seed": seed }))?;
        let mut rows = Vec::new();
        for r in res["results"].as_array().into_iter().flatten() {
            let entry = r["entry_round"].as_u64().unwrap_or(0) as usize;
            let Some(rounds) = r["rounds"].as_array() else {
                rows.push(json!({ "rounds_after_entry": r["rounds_after_entry"], "status": r["status"], "weight_at_least": r["weight_at_least"], "solver_seconds": r["seconds"] }));
                continue;
            };
            let get = |x: &Value, k: &str| x[k].as_u64().unwrap_or(0) as u32;
            let states: Vec<(u32, u32)> = rounds.iter().map(|x| (get(x, "da"), get(x, "de"))).collect();
            let dws: Vec<(usize, u32)> = rounds.iter().filter(|x| get(x, "dw") != 0).map(|x| (x["round"].as_u64().unwrap_or(0) as usize, get(x, "dw"))).collect();
            // A[k], E[k] for k = entry - 3 ..: zero up to the entry round.
            let a = |k: isize| if k <= entry as isize { 0 } else { states[k as usize - entry - 1].0 };
            let e = |k: isize| if k <= entry as isize { 0 } else { states[k as usize - entry - 1].1 };
            let mut log2_product = 0.0;
            let mut per_round = Vec::new();
            for (j, x) in rounds.iter().enumerate() {
                let t = entry + j;
                let ti = t as isize;
                let din: State = [a(ti), a(ti - 1), a(ti - 2), a(ti - 3), e(ti), e(ti - 1), e(ti - 2), e(ti - 3)];
                let cost = get(x, "cost");
                let n = 1u64 << (cost + 10).clamp(20, round_max);
                let k = measure_round(din, get(x, "dw"), states[j], t, n, seed);
                let m = ci_json(k, n);
                if k == 0 {
                    // Not measurable at this size: the model is not confirmed for this round.
                    counterexamples.push(json!({ "start": start, "rounds_after_entry": r["rounds_after_entry"], "round": t, "model_cost": cost, "samples": n, "followers": 0 }));
                }
                log2_product += m["log2_p"].as_f64().unwrap_or(-(n as f64).log2());
                per_round.push(json!({ "round": t, "model_cost": cost, "measured": m }));
            }
            let weight = r["weight"].as_u64().unwrap_or(0);
            let end_to_end = (weight + 6 <= e2e.ilog2() as u64).then(|| ci_json(measure_end_to_end(&dws, &states, entry, e2e, seed), e2e));
            let covered = entry + rounds.len();
            flags.push((covered, log2_product > -32.0));
            rows.push(json!({
                "rounds_after_entry": r["rounds_after_entry"], "last_round": covered - 1, "status": r["status"], "solver_seconds": r["seconds"],
                "model_weight": weight, "measured_markov_log2": log2_product, "end_to_end": end_to_end,
                "message_difference": dws.iter().map(|(t, d)| json!({ "word": t, "xor": format!("{d:#010x}") })).collect::<Vec<_>>(),
                "states": states.iter().map(|(x, y)| json!([format!("{x:#010x}"), format!("{y:#010x}")])).collect::<Vec<_>>(),
                "per_round": per_round,
            }));
        }
        let reach = rows.iter().filter(|r| r["measured_markov_log2"].as_f64().is_some_and(|p| p > -32.0)).filter_map(|r| r["last_round"].as_u64()).max();
        let bound = rows.iter().rev().find_map(|r| r["model_weight"].as_u64().or(r["weight_at_least"].as_u64()).map(|w| (r["rounds_after_entry"].clone(), w, r["status"].clone())));
        summary.push(format!(
            "Start {start}: optimal weights by rounds after entry {:?}; last round reached at measured probability >= 2^-32: {}; largest searched: {} rounds, weight {}{}.",
            rows.iter().map(|r| r["model_weight"].as_u64().map_or(format!(">={}", r["weight_at_least"]), |w| w.to_string())).collect::<Vec<_>>(),
            reach.map_or("none".into(), |r| format!("round {r}")),
            bound.as_ref().map_or(json!(null), |b| b.0.clone()), bound.as_ref().map_or(0, |b| b.1), bound.as_ref().map_or(String::new(), |b| format!(" ({})", b.2.as_str().unwrap_or(""))),
        ));
        obs.push(json!({ "start": start, "characteristics": rows, "z3_version": res["z3_version"] }));
    }
    summary.push(format!(
        "Identities (all templates): 4-round H7 - bswap(nonce) constant: {}; 5-round H7 formula: {}.",
        identities["four_round"]["status"].as_str().unwrap_or("?"), identities["five_round"]["status"].as_str().unwrap_or("?"),
    ));
    let det = json!({ "starts": obs.iter().map(|o| json!(o["characteristics"].as_array().map(|c| c.iter().map(|r| json!([r["model_weight"], r["weight_at_least"], r["states"]])).collect::<Vec<_>>()))).collect::<Vec<_>>(), "identities": [identities["four_round"]["status"], identities["five_round"]["status"]] });
    let mut o = Outcome::new(json!({ "z3_version": z3, "characteristics": obs, "identities": identities }), det, flags, summary);
    o.counterexamples = counterexamples;
    Ok(o)
}

/// The 5-round H7 formula of the identity proof, in Rust (third implementation).
fn five_round_formula(header: &[u8; 80], nonce: u32) -> u32 {
    let mid = bitcoin_header::HeaderMidstate::with_rounds(header, 5);
    let mut w = [0u32; 16];
    w[..3].copy_from_slice(&mid.tail);
    let mut s = mid.state;
    for t in 0..3 {
        s = round(&s, K[t], w[t]);
    }
    let [a3, a2, a1, a0, e3, e2, e1, e0] = s;
    let maj = sha256_core::maj;
    let (sig0, sig1) = (sha256_core::big_sigma0, big_sigma1);
    let nh = nonce.swap_bytes();
    let p = e0.wrapping_add(sig1(e3)).wrapping_add(ch(e3, e2, e1)).wrapping_add(K[3]).wrapping_add(sig0(a3)).wrapping_add(maj(a3, a2, a1));
    let q = a0.wrapping_add(e0).wrapping_add(sig1(e3)).wrapping_add(ch(e3, e2, e1)).wrapping_add(K[3]);
    let (a4, e4) = (p.wrapping_add(nh), q.wrapping_add(nh));
    let a5 = [sig1(e4), ch(e4, e3, e2), K[4], 0x8000_0000, sig0(a4), maj(a4, a3, a2)].iter().fold(e1, |x, y| x.wrapping_add(*y));
    let c0 = [IV[7], big_sigma1(IV[4]), ch(IV[4], IV[5], IV[6]), K[0]].iter().fold(IV[3], |x, y| x.wrapping_add(*y));
    let x = c0.wrapping_add(mid.state[0]).wrapping_add(a5);
    let k_star = [IV[2], IV[6], K[1], mid.state[1], p].iter().fold(IV[7], |x, y| x.wrapping_add(*y));
    k_star.wrapping_add(nh).wrapping_add(sig1(x)).wrapping_add(ch(x, IV[4], IV[5]))
}

pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let ind = verification::independent::Sha256::default();
    let h7 = |h: &[u8; 80], r: usize| {
        let d = ind.sha256d(h, r);
        u32::from_be_bytes([d[28], d[29], d[30], d[31]])
    };
    let mut problems = Vec::new();
    for i in 0..4096u64 {
        let mut rng = SplitMix64::stream(seed ^ 0x1de, i);
        let mut h: [u8; 80] = rng.bytes();
        let (n1, n2) = (rng.next_u32(), rng.next_u32());
        h[76..80].copy_from_slice(&n1.to_le_bytes());
        let (f1, g1) = (h7(&h, 4).wrapping_sub(n1.swap_bytes()), h7(&h, 5));
        let formula = five_round_formula(&h, n1);
        h[76..80].copy_from_slice(&n2.to_le_bytes());
        if f1 != h7(&h, 4).wrapping_sub(n2.swap_bytes()) {
            problems.push(format!("4-round identity fails on sample {i}"));
        }
        if g1 != formula {
            problems.push(format!("5-round formula fails on sample {i}"));
        }
        if problems.len() > 4 {
            break;
        }
    }
    // Positive control for the measurement code: the MSB template costs 2^-11 at the round after entry.
    let n = 1u64 << p_u64(params, "round_samples_max_log2")?.min(24);
    let msb_in: State = [0x8000_0000, 0, 0, 0, 0x8000_0000, 0, 0, 0];
    let s1 = big_sigma1(0x8000_0000);
    let s0 = sha256_core::big_sigma0(0x8000_0000);
    let k = measure_round(msb_in, 0, (s1 | s0, s1), 4, n, seed);
    let p = k as f64 / n as f64;
    if !(2f64.powi(-11) * 0.8..2f64.powi(-11) * 1.25).contains(&p) {
        problems.push(format!("MSB control measured 2^{:.2}, expected 2^-11", p.log2()));
    }
    let proved = ["four_round", "five_round"].iter().all(|k| outcome.observations["identities"][k]["status"] == "proved");
    if !proved {
        problems.push("an identity was not proved by z3".into());
    }
    Ok(Verification {
        method: "4- and 5-round identities rechecked with the independent SHA-256 over 4096 random headers (the 5-round formula re-derived in Rust); measurement positive control: MSB template at 2^-11".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { format!("identities hold on 4096 headers; MSB control 2^{:.3}", p.log2()) } else { problems.join("; ") },
    })
}
