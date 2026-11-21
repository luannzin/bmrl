//! Avalanche (strict avalanche criterion) and XOR-differential measurements on
//! the SHA-256 compression function with a configurable number of rounds.
//!
//! Bit numbering: input bit `j` is bit `j % 32` (LSB = 0) of message word
//! `j / 32`; output bit `o` is bit `o % 32` of output word `o / 32`.
//!
//! All counts are integers reduced across threads, so results are identical
//! for any thread count. Sample `i` uses `SplitMix64::stream(seed, i)`.

#![forbid(unsafe_code)]

pub mod characteristic;

use rayon::prelude::*;
use sha256_core::{State, compress_traced, compress_words};
use statistical_engine::{ChiSquare, SplitMix64, binomial_half_pmf, chi_square_gof, two_sided_p, wilson};
use std::collections::HashMap;

pub const IN_BITS: usize = 512;
pub const OUT_BITS: usize = 256;
const CHUNK: u64 = 64;

/// Random chaining value and message block for sample `i`.
pub fn sample(seed: u64, i: u64) -> (State, [u32; 16]) {
    let mut rng = SplitMix64::stream(seed, i);
    (rng.words(), rng.words())
}

fn chunks(samples: u64) -> impl ParallelIterator<Item = std::ops::Range<u64>> {
    (0..samples.div_ceil(CHUNK)).into_par_iter().map(move |c| c * CHUNK..((c + 1) * CHUNK).min(samples))
}

fn add_into(a: &mut [u64], b: &[u64]) {
    a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
}

/// Raw avalanche counts for one round count.
#[derive(Clone, Debug)]
pub struct Avalanche {
    pub rounds: usize,
    pub samples: u64,
    /// `flips[j * OUT_BITS + o]`: samples where flipping input bit `j` flipped output bit `o`.
    pub flips: Vec<u64>,
    /// Histogram of output-difference Hamming weight over all (sample, input bit) pairs.
    pub weight_hist: Vec<u64>,
}

/// Flip each of the 512 message bits of `samples` random (cv, block) pairs.
pub fn avalanche(rounds: usize, samples: u64, seed: u64) -> Avalanche {
    let (flips, weight_hist) = chunks(samples)
        .map(|range| {
            let mut flips = vec![0u64; IN_BITS * OUT_BITS];
            let mut hist = vec![0u64; OUT_BITS + 1];
            for i in range {
                let (cv, m) = sample(seed, i);
                let base = compress_words(&cv, &m, rounds);
                for j in 0..IN_BITS {
                    let mut m2 = m;
                    m2[j / 32] ^= 1 << (j % 32);
                    let out = compress_words(&cv, &m2, rounds);
                    let row = &mut flips[j * OUT_BITS..(j + 1) * OUT_BITS];
                    let mut weight = 0;
                    for w in 0..8 {
                        let mut d = base[w] ^ out[w];
                        weight += d.count_ones() as usize;
                        while d != 0 {
                            row[w * 32 + d.trailing_zeros() as usize] += 1;
                            d &= d - 1;
                        }
                    }
                    hist[weight] += 1;
                }
            }
            (flips, hist)
        })
        .reduce(
            || (vec![0u64; IN_BITS * OUT_BITS], vec![0u64; OUT_BITS + 1]),
            |(mut fa, mut ha), (fb, hb)| {
                add_into(&mut fa, &fb);
                add_into(&mut ha, &hb);
                (fa, ha)
            },
        );
    Avalanche { rounds, samples, flips, weight_hist }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AvalancheStats {
    pub rounds: usize,
    pub samples: u64,
    pub mean_flip_probability: f64,
    /// Largest |p_jo - 1/2| over all 131072 (input, output) bit pairs.
    pub max_bias: f64,
    pub max_abs_z: f64,
    /// (input bit, output bit, flip count) of the pair with the largest |z|.
    pub worst_pair: (usize, usize, u64),
    /// Pairs whose two-sided p-value is below `alpha / 131072` (Bonferroni).
    pub significant_pairs: u64,
    /// Pairs that never flipped.
    pub never_flipped_pairs: u64,
    /// Pairs that always flipped.
    pub always_flipped_pairs: u64,
    /// Message words whose bits had no effect on any output bit.
    pub inert_message_words: Vec<usize>,
    /// Output-difference weight distribution vs Binomial(256, 1/2).
    pub weight_gof: ChiSquare,
    /// Any Bonferroni-significant pair, or weight distribution rejected at `alpha`.
    pub distinguishable: bool,
}

pub fn analyze_avalanche(a: &Avalanche, alpha: f64) -> AvalancheStats {
    let n = a.samples as f64;
    let cells = (IN_BITS * OUT_BITS) as f64;
    let threshold = alpha / cells;
    let (mut max_bias, mut max_abs_z, mut significant, mut never, mut always) = (0.0f64, -1.0f64, 0, 0, 0);
    let mut worst_pair = (0, 0, 0);
    for (cell, &c) in a.flips.iter().enumerate() {
        let z = (c as f64 - n / 2.0) / (n / 4.0).sqrt();
        if z.abs() > max_abs_z {
            max_abs_z = z.abs();
            worst_pair = (cell / OUT_BITS, cell % OUT_BITS, c);
        }
        max_bias = max_bias.max((c as f64 / n - 0.5).abs());
        if two_sided_p(z) < threshold {
            significant += 1;
        }
        never += (c == 0) as u64;
        always += (c == a.samples) as u64;
    }
    let inert_message_words = (0..16)
        .filter(|w| a.flips[w * 32 * OUT_BITS..(w + 1) * 32 * OUT_BITS].iter().all(|&c| c == 0))
        .collect();
    let total: u64 = a.flips.iter().sum();
    let weight_gof = chi_square_gof(&a.weight_hist, &binomial_half_pmf(OUT_BITS as u32));
    AvalancheStats {
        rounds: a.rounds,
        samples: a.samples,
        mean_flip_probability: total as f64 / (n * cells),
        max_bias,
        max_abs_z,
        worst_pair,
        significant_pairs: significant,
        never_flipped_pairs: never,
        always_flipped_pairs: always,
        inert_message_words,
        distinguishable: significant > 0 || weight_gof.p_value < alpha,
        weight_gof,
    }
}

/// XOR-differential profile for a fixed message difference.
#[derive(Clone, Debug)]
pub struct Differential {
    pub rounds: usize,
    pub samples: u64,
    pub delta: [u32; 16],
    /// Number of distinct output differences observed.
    pub distinct: u64,
    /// Most frequent output differences, count descending then value ascending.
    pub top: Vec<(State, u64)>,
    pub weight_hist: Vec<u64>,
    /// Sum over samples of the state-difference Hamming weight after round t (index 0 = input).
    pub round_weight_sum: Vec<u64>,
}

fn weight(s: &State) -> u64 {
    s.iter().map(|w| w.count_ones() as u64).sum()
}

pub fn differential(rounds: usize, delta: [u32; 16], samples: u64, seed: u64, top_k: usize) -> Differential {
    type Acc = (HashMap<State, u64>, Vec<u64>, Vec<u64>);
    let empty = || -> Acc { (HashMap::new(), vec![0; OUT_BITS + 1], vec![0; rounds + 1]) };
    let (counts, weight_hist, round_weight_sum) = chunks(samples)
        .map(|range| {
            let (mut counts, mut hist, mut per_round) = empty();
            for i in range {
                let (cv, m) = sample(seed, i);
                let m2: [u32; 16] = std::array::from_fn(|k| m[k] ^ delta[k]);
                let (t1, t2) = (compress_traced(&cv, &m, rounds), compress_traced(&cv, &m2, rounds));
                for (t, (s1, s2)) in t1.states.iter().zip(&t2.states).enumerate() {
                    per_round[t] += weight(&std::array::from_fn(|k| s1[k] ^ s2[k]));
                }
                let d: State = std::array::from_fn(|k| t1.output[k] ^ t2.output[k]);
                hist[weight(&d) as usize] += 1;
                *counts.entry(d).or_insert(0) += 1;
            }
            (counts, hist, per_round)
        })
        .reduce(empty, |(mut ca, mut ha, mut ra), (cb, hb, rb)| {
            for (k, v) in cb {
                *ca.entry(k).or_insert(0) += v;
            }
            add_into(&mut ha, &hb);
            add_into(&mut ra, &rb);
            (ca, ha, ra)
        });
    let distinct = counts.len() as u64;
    let mut top: Vec<(State, u64)> = counts.into_iter().collect();
    top.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top.truncate(top_k);
    Differential { rounds, samples, delta, distinct, top, weight_hist, round_weight_sum }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DifferentialStats {
    pub rounds: usize,
    pub samples: u64,
    pub distinct: u64,
    pub top_count: u64,
    /// Empirical probability of the most frequent output difference.
    pub top_probability: f64,
    pub top_probability_ci95: (f64, f64),
    pub mean_output_weight: f64,
    pub mean_state_weight_per_round: Vec<f64>,
    pub weight_gof: ChiSquare,
    /// A repeated output difference (impossible in practice for an ideal
    /// 256-bit function at these sample sizes), or weight distribution
    /// rejected at `alpha`.
    pub distinguishable: bool,
}

pub fn analyze_differential(d: &Differential, alpha: f64) -> DifferentialStats {
    let n = d.samples as f64;
    let top_count = d.top.first().map_or(0, |t| t.1);
    let weight_gof = chi_square_gof(&d.weight_hist, &binomial_half_pmf(OUT_BITS as u32));
    let mean_output_weight = d.weight_hist.iter().enumerate().map(|(w, c)| w as f64 * *c as f64).sum::<f64>() / n;
    DifferentialStats {
        rounds: d.rounds,
        samples: d.samples,
        distinct: d.distinct,
        top_count,
        top_probability: top_count as f64 / n,
        top_probability_ci95: wilson(top_count, d.samples, statistical_engine::Z95),
        mean_output_weight,
        mean_state_weight_per_round: d.round_weight_sum.iter().map(|&s| s as f64 / n).collect(),
        distinguishable: top_count >= 2 || weight_gof.p_value < alpha,
        weight_gof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avalanche_is_deterministic_across_thread_counts() {
        let a = avalanche(8, 40, 7);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let b = pool.install(|| avalanche(8, 40, 7));
        assert_eq!(a.flips, b.flips);
        assert_eq!(a.weight_hist, b.weight_hist);
    }

    #[test]
    fn low_rounds_leave_late_message_words_inert() {
        // Word t first enters at round t, so after 4 rounds words 4..15 are inert.
        let s = analyze_avalanche(&avalanche(4, 16, 1), 0.01);
        assert_eq!(s.inert_message_words, (4..16).collect::<Vec<_>>());
        assert!(s.distinguishable);
    }

    #[test]
    fn last_word_difference_is_deterministic_one_round_after_entry() {
        // A difference in W15 enters at round 15; after 16 rounds the output
        // difference depends on carries but the input states are identical.
        let mut delta = [0u32; 16];
        delta[15] = 0x8000_0000;
        let d = differential(16, delta, 64, 3, 3);
        // MSB difference in W15 propagates to a and e without carries.
        assert_eq!(d.distinct, 1);
        assert_eq!(d.top[0].0, [0x8000_0000, 0, 0, 0, 0x8000_0000, 0, 0, 0]);
        assert_eq!(d.round_weight_sum[15], 0);
    }
}
