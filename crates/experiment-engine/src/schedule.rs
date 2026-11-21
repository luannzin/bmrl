//! Message-schedule structure: GF(2) rank and low-weight linearized
//! differences, carry effect, statistical dependence between expanded words,
//! and Bitcoin-header-specific redundancy (which schedule work does not
//! depend on the nonce or the inner digest), with a measured comparison of a
//! constant-folded outer schedule against the generic one.

use crate::{Definition, FULL_ROUNDS, Outcome, Verification, p_f64, p_u64};
use algebraic_engine::{rank, schedule_rows, unit_message, xor_schedule};
use anyhow::Result;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::{message_schedule, small_sigma0, small_sigma1};
use statistical_engine::{SplitMix64, binomial_z, two_sided_p};
use std::hint::black_box;
use std::time::Instant;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-SCHED-01",
        primitive: "sha256-message-schedule,bitcoin-header-sha256d",
        name: "Structure and redundancy of the SHA-256 message schedule",
        // v2: fixed σ0(256) constant in the folded outer schedule; verification now requires folding parity.
        version: 2,
        hypothesis: "The SHA-256 message schedule has exploitable structure: low-weight linearized expanded differences, statistical dependence between expanded words, or nonce-independent work in Bitcoin header hashing beyond what the verified baseline kernel already precomputes.",
        null_hypothesis: "Expanded words of random messages are unbiased and pairwise independent; all low-weight message differences expand to high-weight differences; the baseline already removes all nonce-independent schedule work.",
        assumptions: &[
            "Linearized schedule: modular additions replaced by XOR; low weights there are necessary, not sufficient, for low-weight real differences.",
            "Exhaustive over message differences of weight 1 and 2 only (131,328 candidates).",
            "Statistical tests: bit bias of W16..W63 and agreement of consecutive words, Bonferroni over all tests.",
            "Bitcoin second header block: W0..W2 fixed per job, W3 = nonce, padding words constant. Outer block: W0..W7 = inner digest (varies per nonce), padding constant.",
            "Timing comparisons are single-thread, release build, median of repeated batches; they are engineering measurements, not cryptographic results.",
        ],
        baseline: "Verified cpu-backend scalar kernel: hoists W16, W17 and rounds 0..2 of the second header block; computes the outer schedule with the generic recurrence.",
        methodology: "Compute GF(2) ranks of schedule windows and null-space dimensions; enumerate weight-1/2 message differences through the linearized schedule; measure real-vs-linearized agreement and bit statistics on random messages; propagate nonce/digest dependence through the recurrence to count hoistable operations; time generic vs constant-folded outer schedule.",
        implementation: &["algebraic_engine::{xor_schedule, schedule_rows, rank}", "sha256_core::message_schedule"],
        dataset: "n random messages from SplitMix64::stream(seed, i); timing on header-like blocks.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "samples": if quick { 4096 } else { 1 << 16 },
        "timing_iterations": if quick { 1 << 14 } else { 1 << 20 },
        "alpha": 0.01,
        "reproduce": true,
    })
}

/// Which message words vary (true) for a block type.
fn variable_inputs(block: &str) -> [bool; 16] {
    let mut v = [false; 16];
    match block {
        "header-second-block" => v[3] = true,
        _ => v[..8].iter_mut().for_each(|x| *x = true),
    }
    v
}

/// Constant words that are known zero.
fn zero_inputs(block: &str) -> [bool; 16] {
    let mut z = [false; 16];
    match block {
        "header-second-block" => (5..15).for_each(|i| z[i] = true),
        _ => (9..15).for_each(|i| z[i] = true),
    }
    z
}

/// Per expanded word: varies?, and operation counts naive vs hoisted.
fn redundancy(block: &str) -> Value {
    let mut var = [false; 64];
    let mut zero = [false; 64];
    var[..16].copy_from_slice(&variable_inputs(block));
    zero[..16].copy_from_slice(&zero_inputs(block));
    let (mut adds, mut sigmas, mut hoisted_words) = (0u32, 0u32, Vec::new());
    for t in 16..64 {
        // Terms: σ1(W[t-2]), W[t-7], σ0(W[t-15]), W[t-16].
        let terms = [(t - 2, true), (t - 7, false), (t - 15, true), (t - 16, false)];
        let variable: Vec<_> = terms.iter().filter(|(i, _)| var[*i]).collect();
        let const_nonzero = terms.iter().any(|(i, _)| !var[*i] && !zero[*i]);
        var[t] = !variable.is_empty();
        zero[t] = !var[t] && !const_nonzero;
        if var[t] {
            adds += variable.len() as u32 - 1 + const_nonzero as u32;
            sigmas += variable.iter().filter(|(_, s)| *s).count() as u32;
        } else {
            hoisted_words.push(t);
        }
    }
    json!({
        "block": block,
        "naive_adds": 48 * 3,
        "naive_sigma_evaluations": 48 * 2,
        "minimal_adds_per_nonce": adds,
        "minimal_sigma_evaluations_per_nonce": sigmas,
        "nonce_independent_words": hoisted_words,
        "variable_words": (16..64).filter(|&t| var[t]).collect::<Vec<_>>(),
    })
}

/// Generic outer schedule exactly as the baseline kernel writes it.
#[inline(never)]
fn outer_generic(inner: &[u32; 8]) -> [u32; 64] {
    let mut w = [0u32; 64];
    w[..8].copy_from_slice(inner);
    w[8] = 0x8000_0000;
    w[15] = 256;
    for t in 16..64 {
        w[t] = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
    }
    w
}

/// Outer schedule with every zero term and constant subexpression folded.
/// Constant terms are written as calls on literals (the compiler folds them);
/// hand-computed constants caused an error in definition version 1.
#[inline(never)]
fn outer_folded(x: &[u32; 8]) -> [u32; 64] {
    let s1_256 = small_sigma1(256);
    let s0_256 = small_sigma0(256);
    let s0_8000 = small_sigma0(0x8000_0000);
    let mut w = [0u32; 64];
    w[..8].copy_from_slice(x);
    w[8] = 0x8000_0000;
    w[15] = 256;
    // W9..W14 = 0: drop those terms.
    w[16] = small_sigma0(w[1]).wrapping_add(w[0]);
    w[17] = s1_256.wrapping_add(small_sigma0(w[2])).wrapping_add(w[1]);
    w[18] = small_sigma1(w[16]).wrapping_add(small_sigma0(w[3])).wrapping_add(w[2]);
    w[19] = small_sigma1(w[17]).wrapping_add(small_sigma0(w[4])).wrapping_add(w[3]);
    w[20] = small_sigma1(w[18]).wrapping_add(small_sigma0(w[5])).wrapping_add(w[4]);
    w[21] = small_sigma1(w[19]).wrapping_add(small_sigma0(w[6])).wrapping_add(w[5]);
    w[22] = small_sigma1(w[20]).wrapping_add(256).wrapping_add(small_sigma0(w[7])).wrapping_add(w[6]);
    w[23] = small_sigma1(w[21]).wrapping_add(w[16]).wrapping_add(s0_8000).wrapping_add(w[7]);
    w[24] = small_sigma1(w[22]).wrapping_add(w[17]).wrapping_add(0x8000_0000);
    w[25] = small_sigma1(w[23]).wrapping_add(w[18]);
    w[26] = small_sigma1(w[24]).wrapping_add(w[19]);
    w[27] = small_sigma1(w[25]).wrapping_add(w[20]);
    w[28] = small_sigma1(w[26]).wrapping_add(w[21]);
    w[29] = small_sigma1(w[27]).wrapping_add(w[22]);
    w[30] = small_sigma1(w[28]).wrapping_add(w[23]).wrapping_add(s0_256);
    w[31] = small_sigma1(w[29]).wrapping_add(w[24]).wrapping_add(small_sigma0(w[16])).wrapping_add(256);
    for t in 32..64 {
        w[t] = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
    }
    w
}

fn time_ns(iters: u64, mut f: impl FnMut(u64)) -> f64 {
    let mut runs = Vec::new();
    for _ in 0..7 {
        let t = Instant::now();
        for i in 0..iters {
            f(i);
        }
        runs.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    runs.sort_by(f64::total_cmp);
    runs[3]
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let n = p_u64(params, "samples")?;
    let alpha = p_f64(params, "alpha")?;

    // 1. GF(2) ranks.
    let window_ranks: Vec<usize> = (0..=48).map(|i| rank(&schedule_rows(i..i + 16))).collect();
    let null_dims: Vec<usize> = (1..=16).map(|j| 512 - rank(&schedule_rows(16..16 + j))).collect();

    // 2. Low-weight linearized differences (weight-1 and weight-2 messages).
    let singles: Vec<[u32; 64]> = (0..512).map(|j| xor_schedule(&unit_message(j))).collect();
    let weight = |w: &[u32; 64]| w[16..].iter().map(|x| x.count_ones()).sum::<u32>();
    let zero_run = |w: &[u32; 64]| w[16..].iter().take_while(|&&x| x == 0).count();
    let (best_single, best_single_w) = singles.iter().enumerate().map(|(j, s)| (j, weight(s))).min_by_key(|x| x.1).expect("512 singles");
    let best_pair = (0..512usize)
        .into_par_iter()
        .map(|a| {
            ((a + 1)..512)
                .map(|b| {
                    let x: [u32; 64] = std::array::from_fn(|t| singles[a][t] ^ singles[b][t]);
                    (weight(&x), zero_run(&x), a, b)
                })
                .min()
                .unwrap_or((u32::MAX, 0, a, a))
        })
        .min()
        .expect("pairs");
    let longest_zero_run = (0..512usize)
        .into_par_iter()
        .map(|a| ((a + 1)..512).map(|b| {
            let x: [u32; 64] = std::array::from_fn(|t| singles[a][t] ^ singles[b][t]);
            zero_run(&x)
        }).max().unwrap_or(0).max(zero_run(&singles[a])))
        .max()
        .unwrap_or(0);

    // 3/4. Carry effect and statistics on real schedules.
    let msgs: Vec<[u32; 16]> = (0..n).map(|i| SplitMix64::stream(seed, i).words()).collect();
    let (ones, agree_lin, agree_next) = msgs
        .par_iter()
        .fold(
            || (vec![0u64; 64 * 32], vec![0u64; 64], vec![0u64; 64]),
            |(mut ones, mut lin, mut next), m| {
                let w = message_schedule(m);
                let x = xor_schedule(m);
                for t in 0..64 {
                    let mut v = w[t];
                    while v != 0 {
                        ones[t * 32 + v.trailing_zeros() as usize] += 1;
                        v &= v - 1;
                    }
                    lin[t] += 32 - (w[t] ^ x[t]).count_ones() as u64;
                    if t < 63 {
                        next[t] += 32 - (w[t] ^ w[t + 1]).count_ones() as u64;
                    }
                }
                (ones, lin, next)
            },
        )
        .reduce(
            || (vec![0u64; 64 * 32], vec![0u64; 64], vec![0u64; 64]),
            |(mut a, mut b, mut c), (x, y, z)| {
                a.iter_mut().zip(x).for_each(|(p, q)| *p += q);
                b.iter_mut().zip(y).for_each(|(p, q)| *p += q);
                c.iter_mut().zip(z).for_each(|(p, q)| *p += q);
                (a, b, c)
            },
        );
    let tests = (48 * 32 + 47) as f64;
    let threshold = alpha / tests;
    let biased_bits = (16 * 32..64 * 32).filter(|&i| two_sided_p(binomial_z(ones[i], n, 0.5)) < threshold).count();
    let correlated_pairs: Vec<usize> = (16..63).filter(|&t| two_sided_p(binomial_z(agree_next[t], n * 32, 0.5)) < threshold).collect();
    let linear_agreement: Vec<f64> = (0..64).map(|t| agree_lin[t] as f64 / (n * 32) as f64).collect();
    let last_linear = (16..64).filter(|&t| two_sided_p(binomial_z(agree_lin[t], n * 32, 0.5)) < threshold).max();

    // 5. Bitcoin redundancy + measured folding.
    let inner = redundancy("header-second-block");
    let outer = redundancy("header-outer-block");
    let iters = p_u64(params, "timing_iterations")?;
    let inputs: Vec<[u32; 8]> = (0..1024u64).map(|i| SplitMix64::stream(seed ^ 0x0f0, i).words()).collect();
    let mismatches = inputs.iter().filter(|x| outer_generic(x) != outer_folded(x)).count();
    let generic_ns = time_ns(iters, |i| {
        black_box(outer_generic(black_box(&inputs[(i & 1023) as usize])));
    });
    let folded_ns = time_ns(iters, |i| {
        black_box(outer_folded(black_box(&inputs[(i & 1023) as usize])));
    });
    let full_hash_ns = time_ns(iters / 8, |i| {
        let mut st = sha256_core::IV;
        let m: [u32; 16] = std::array::from_fn(|k| inputs[(i & 1023) as usize][k & 7]);
        st = sha256_core::compress_words(&st, &m, 64);
        black_box(sha256_core::compress_words(&st, &m, 64));
    });

    let deviation = biased_bits > 0 || !correlated_pairs.is_empty();
    let flags = vec![(FULL_ROUNDS, deviation)];
    let det = json!({
        "window_ranks": window_ranks, "null_dims": null_dims,
        "best_single": [best_single, best_single_w], "best_pair": [best_pair.0, best_pair.1, best_pair.2, best_pair.3],
        "longest_zero_run": longest_zero_run, "ones": ones, "agree_lin": agree_lin, "agree_next": agree_next,
        "inner": inner, "outer": outer, "fold_mismatches": mismatches,
    });
    let saving = generic_ns - folded_ns;
    let summary = vec![
        format!("Linearized schedule: every 16-word window has GF(2) rank {} (min over windows), so the expansion is invertible; requiring j words W16.. to vanish leaves null space dimension 512-32j (observed {:?}).", window_ranks.iter().min().unwrap_or(&0), null_dims),
        format!("Lowest linearized expanded weight (W16..W63) from a 1-bit message difference: {best_single_w} (bit {best_single}); from 2-bit: {} (bits {}, {}); longest run of zero expanded words from W16 among weight<=2 differences: {longest_zero_run}.", best_pair.0, best_pair.2, best_pair.3),
        format!("Real vs linearized schedule: agreement significantly above 1/2 last at W{}.", last_linear.map_or("none".into(), |t| t.to_string())),
        format!("Real schedule statistics: {biased_bits} biased bits, consecutive-word correlations at {correlated_pairs:?}."),
        format!("Bitcoin header: second-block words independent of the nonce: {}; the baseline already hoists W16, W17. Outer block: no word is digest-independent, {} adds + {} sigma evaluations per nonce are the minimum vs 144 + 96 naive.", inner["nonce_independent_words"], outer["minimal_adds_per_nonce"], outer["minimal_sigma_evaluations_per_nonce"]),
        if mismatches == 0 {
            format!("Measured (single thread, median of 7): generic outer schedule {generic_ns:.2} ns, constant-folded {folded_ns:.2} ns, difference {saving:.2} ns = {:.1}% of one double compression ({full_hash_ns:.1} ns); folded variant identical to the generic one on all {} inputs.", 100.0 * saving / full_hash_ns, inputs.len())
        } else {
            format!("Folded outer schedule is WRONG on {mismatches} of {} inputs; its timing is meaningless.", inputs.len())
        },
    ];
    let observations = json!({
        "gf2": { "window_ranks": window_ranks, "null_space_dim_when_first_j_words_vanish": null_dims },
        "linearized_low_weight": {
            "best_single": { "message_bit": best_single, "weight_w16_w63": best_single_w },
            "best_pair": { "message_bits": [best_pair.2, best_pair.3], "weight_w16_w63": best_pair.0, "zero_run_from_w16": best_pair.1 },
            "longest_zero_run_from_w16": longest_zero_run,
            "candidates": 512 + 512 * 511 / 2,
        },
        "real_vs_linearized_agreement": linear_agreement,
        "statistics": { "samples": n, "biased_bits_w16_w63": biased_bits, "correlated_consecutive_words": correlated_pairs, "threshold_p": threshold },
        "bitcoin_header_redundancy": { "second_block": inner, "outer_block": outer },
        "outer_schedule_folding": {
            "generic_ns": generic_ns, "folded_ns": folded_ns, "saving_ns": saving,
            "double_compression_ns": full_hash_ns, "saving_fraction_of_hash": saving / full_hash_ns,
            "verified_identical_inputs": inputs.len(), "mismatches": mismatches,
            "note": "timing is an engineering measurement and is excluded from the reproducibility digest",
        },
    });
    Ok(Outcome::new(observations, det, flags, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folded_outer_schedule_matches_generic() {
        for i in 0..4096u64 {
            let x: [u32; 8] = SplitMix64::stream(5, i).words();
            assert_eq!(outer_folded(&x), outer_generic(&x), "input {i}");
        }
    }
}

/// Independent checks: rank via the transposed matrix; dependency analysis
/// against concrete schedules with varying nonce / digest.
pub fn verify(_params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let mut problems = Vec::new();
    // An optimization is only comparable once it reproduces the baseline exactly.
    let fold = &outcome.observations["outer_schedule_folding"]["mismatches"];
    if fold.as_u64() != Some(0) {
        problems.push(format!("constant-folded outer schedule differs from the generic one on {fold} inputs"));
    }
    // rank(A) == rank(A^T): build column-major rows independently.
    for range in [0..16usize, 16..32, 16..20, 40..56] {
        let rows = schedule_rows(range.clone());
        let width = rows.len();
        let mut cols = vec![vec![0u64; width.div_ceil(64)]; 512];
        for (r, row) in rows.iter().enumerate() {
            for j in 0..512 {
                if row[j / 64] >> (j % 64) & 1 == 1 {
                    cols[j][r / 64] |= 1 << (r % 64);
                }
            }
        }
        if rank(&rows) != rank(&cols) {
            problems.push(format!("rank mismatch for W{range:?}"));
        }
    }
    // Dependency analysis vs concrete schedules.
    for block in ["header-second-block", "header-outer-block"] {
        let rd = redundancy(block);
        let independent: Vec<usize> = rd["nonce_independent_words"].as_array().into_iter().flatten().filter_map(|v| v.as_u64()).map(|v| v as usize).collect();
        let var = variable_inputs(block);
        let zero = zero_inputs(block);
        let mut rng = SplitMix64::stream(seed, 99);
        let mut base: [u32; 16] = rng.words();
        for i in 0..16 {
            if zero[i] {
                base[i] = 0;
            }
        }
        let w0 = message_schedule(&base);
        let mut varies = [false; 64];
        for _ in 0..64 {
            let mut m = base;
            for i in 0..16 {
                if var[i] {
                    m[i] = rng.next_u32();
                }
            }
            let w = message_schedule(&m);
            (0..64).for_each(|t| varies[t] |= w[t] != w0[t]);
        }
        for t in 16..64 {
            if independent.contains(&t) == varies[t] {
                problems.push(format!("{block}: W{t} predicted {} but observed {}", if independent.contains(&t) { "constant" } else { "variable" }, if varies[t] { "variable" } else { "constant" }));
            }
        }
    }
    Ok(Verification {
        method: "GF(2) ranks recomputed on the transposed matrices; nonce/digest dependence of every expanded word checked against 64 concrete schedules with varying inputs".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "all checks consistent".into() } else { problems.join("; ") },
    })
}
