//! Can a validated characteristic reduce the work of Bitcoin header search?
//!
//! A differential characteristic is a statement about pairs (x, x ^ Δ).
//! Mining asks about single inputs: SHA256d(header) <= target. This
//! experiment tests every way the characteristics could matter for that
//! event, on the real header layout (only W0 = merkle tail, W1 = time and
//! W3 = nonce of the second block vary; padding words are fixed):
//!
//! A. Trail search: over single-bit and nonce two-bit differences in those
//!    words, how far does a signed-difference trail survive in the second
//!    header block? The best predictions are measured.
//! B. Neighbour search: given a share-level hit x (k_share leading zero bits),
//!    is the neighbour x ^ Δ a target-level hit (k_target bits) more often
//!    than 2^-k_target? If yes, evaluating neighbours of shares beats fresh
//!    nonces.
//! C. Condition filter: does an input that satisfies the 11 exact round
//!    conditions of the nonce-MSB trail hit the target more often?
//!
//! Each strategy's expected work per target hit is computed from the
//! measurements and compared with exhaustive search over fresh nonces.

use crate::characteristic_audit::{Snapshot, condition_mask, derive};
use crate::smt::meets;
use crate::{Definition, FULL_ROUNDS, Outcome, Verification, p_rounds, p_u64};
use anyhow::Result;
use bitcoin_header::{HeaderMidstate, Target, hash_number_words};
use differential_engine::characteristic::xor_trail;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::{K, round, small_sigma0, small_sigma1};
use statistical_engine::{SplitMix64, Z95, binomial_z, wilson};

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-MINE-01",
        primitive: crate::primitive::HEADER,
        name: "Trail-to-search conversion for SHA256d(header) <= target",
        version: 1,
        hypothesis: "A validated reduced-round characteristic, or neighbour relations along trail differences in the header words a miner controls, raises the conditional probability of the Bitcoin target event enough to lower the expected work per target hit below exhaustive search.",
        null_hypothesis: "For every tested difference and condition set, the target-hit probability of neighbours of share hits and of condition-satisfying inputs equals 2^-k_target, so every derived strategy needs at least the exhaustive work per hit.",
        assumptions: &[
            "Header layout: second-block W0 (merkle tail), W1 (time), W3 (nonce) vary; W2 (bits) and padding are fixed. The first block's midstate is random per header.",
            "A hit means the hash, read as Bitcoin's little-endian 256-bit number, has k leading zero bits, i.e. it is <= 2^(256-k) - 1: the real target comparison for a target of that form.",
            "Reduced-round variants cut all three compressions to r rounds; conditions are taken from the r-round computation itself.",
            "Expected work counts SHA256d evaluations; a condition check costs 5/128 of one (5 of 128 compression rounds) and is charged.",
            "Neighbour strategy cost treats each neighbour as a fresh candidate (a real implementation scans only nonces whose flipped bits are 0, so neighbours fall outside the scan); the measured conditional rate is what decides it.",
            "Significance: two-sided z against the null rate, Bonferroni over all round counts and tests.",
        ],
        baseline: "Exhaustive search over fresh nonces: 2^k_target SHA256d evaluations per target hit (measured on the same scan).",
        methodology: "A: trail search with the signed estimator, top trails measured on header-structured pairs. B: per round count, scan nonces of random headers until `share_hits` share-level hits; evaluate every neighbour x ^ Δ for Δ in the 32 nonce bits plus the top trail differences; count target-level hits. C: during the same scan, evaluate the 11 conditions of the nonce-MSB trail on each nonce and split target hits by whether they hold. Strategy costs from these counts.",
        implementation: &["experiment_engine::trail_search", "experiment_engine::characteristic_audit::derive", "bitcoin_header::HeaderMidstate::with_rounds"],
        dataset: "Header h: 80 random bytes from SplitMix64::stream(seed, h); nonces i * 0x9e3779b1 for i = 0, 1, ... (a bijection on 32 bits), at most 16x the expected scan per header.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": [4, 5, 6, 8, 12, 16, 24, 64],
        "k_share": 8,
        "k_target": 12,
        "share_hits": if quick { 1 << 12 } else { 1 << 20 },
        "trail_budget_bits": 24,
        "trail_top": 8,
        "trail_validation_pairs": if quick { 1 << 16 } else { 1 << 22 },
        "alpha": 0.01,
        "reproduce": true,
    })
}

/// A difference in the second header block: word index (0, 1 or 3) to XOR mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Delta {
    w0: u32,
    w1: u32,
    w3: u32,
}

impl Delta {
    fn message(&self) -> [u32; 16] {
        let mut m = [0u32; 16];
        (m[0], m[1], m[3]) = (self.w0, self.w1, self.w3);
        m
    }

    fn label(&self) -> String {
        let bits = |w: u32| (0..32).rev().filter(|i| w >> i & 1 == 1).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        [("W0", self.w0), ("W1", self.w1), ("W3", self.w3)]
            .iter()
            .filter(|(_, w)| *w != 0)
            .map(|(n, w)| format!("{n}[{}]", bits(*w)))
            .collect::<Vec<_>>()
            .join("+")
    }

    /// The neighbour header: same midstate, tail words and nonce XORed.
    fn apply(&self, mid: &HeaderMidstate, nonce: u32) -> (HeaderMidstate, u32) {
        let mut m = *mid;
        m.tail[0] ^= self.w0;
        m.tail[1] ^= self.w1;
        // W3 is the nonce read big-endian.
        (m, nonce ^ self.w3.swap_bytes())
    }
}

fn header(seed: u64, h: u64) -> [u8; 80] {
    SplitMix64::stream(seed, h).bytes()
}

/// Signed-estimator reach of a difference: last round index whose cumulative
/// estimate stays within `budget` bits, and that estimate.
fn reach(d: &Delta, budget: f64) -> (usize, f64) {
    let t = xor_trail(&d.message(), FULL_ROUNDS);
    let cum = t.cumulative_log2_modular();
    let r = (0..=FULL_ROUNDS).take_while(|&r| cum[r] >= -budget).last().unwrap_or(0);
    (r, cum[r])
}

/// Measured follow rate of the trail of `d` through `rounds` on header-structured pairs.
fn follow_rate(d: &Delta, rounds: usize, n: u64, seed: u64) -> u64 {
    let trail = xor_trail(&d.message(), rounds);
    let dm = d.message();
    (0..n)
        .into_par_iter()
        .filter(|&i| {
            let mut rng = SplitMix64::stream(seed, i);
            let cv: [u32; 8] = rng.words();
            let mut w1 = [0u32; 64];
            w1[..4].copy_from_slice(&rng.words::<4>());
            w1[4] = 0x8000_0000;
            w1[15] = 640;
            let mut w2 = w1;
            for k in 0..16 {
                w2[k] ^= dm[k];
            }
            let (mut s1, mut s2) = (cv, cv);
            for t in 0..rounds {
                if t >= 16 {
                    for w in [&mut w1, &mut w2] {
                        w[t] = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
                    }
                }
                s1 = round(&s1, K[t], w1[t]);
                s2 = round(&s2, K[t], w2[t]);
                if (w1[t] ^ w2[t]) != trail.delta_w[t] || (0..8).any(|k| s1[k] ^ s2[k] != trail.states[t + 1][k]) {
                    return false;
                }
            }
            true
        })
        .count() as u64
}

#[derive(Clone)]
struct Tally {
    scanned: u64,
    target_hits: u64,
    share_hits: u64,
    /// Per neighbour difference: target-level hits among neighbours of share hits.
    neighbour_target: Vec<u64>,
    /// Condition filter: scanned nonces satisfying all conditions, and hits
    /// among all nonces / among those, at each level of [`FILTER_LEVELS`].
    cond_scanned: u64,
    level_hits: [u64; 3],
    cond_level_hits: [u64; 3],
}

/// Leading-zero levels at which the condition filter is measured: a filter
/// correlated with the hash's leading bits shows up at low levels first.
fn filter_levels(ks: u32, kt: u32) -> [u32; 3] {
    [4.min(ks), ks, kt]
}

impl Tally {
    fn new(nd: usize) -> Self {
        Self { scanned: 0, target_hits: 0, share_hits: 0, neighbour_target: vec![0; nd], cond_scanned: 0, level_hits: [0; 3], cond_level_hits: [0; 3] }
    }

    fn add(mut self, o: Tally) -> Self {
        self.scanned += o.scanned;
        self.target_hits += o.target_hits;
        self.share_hits += o.share_hits;
        self.neighbour_target.iter_mut().zip(&o.neighbour_target).for_each(|(a, b)| *a += b);
        self.cond_scanned += o.cond_scanned;
        for k in 0..3 {
            self.level_hits[k] += o.level_hits[k];
            self.cond_level_hits[k] += o.cond_level_hits[k];
        }
        self
    }
}

/// Odd multiplier: `i * SCRAMBLE` is a bijection on u32 that varies every
/// nonce byte from the first steps (a scan from 0 leaves the top byte fixed
/// for 2^24 nonces, which reduced-round structure turns into a stall).
const SCRAMBLE: u32 = 0x9e37_79b1;

/// Scan one header's nonces in scrambled order until `want` share hits or
/// `cap` nonces.
fn scan_header(mid: &HeaderMidstate, deltas: &[Delta], conds: Option<&[crate::characteristic_audit::Cond]>, ks: u32, kt: u32, want: u64, cap: u64) -> Tally {
    let mut t = Tally::new(deltas.len());
    let full_mask = conds.map(|c| (1usize << c.len()) - 1);
    let neighbours: Vec<(HeaderMidstate, u32)> = deltas.iter().map(|d| d.apply(mid, 0)).collect();
    for i in 0..=u32::MAX {
        if t.share_hits >= want || t.scanned >= cap {
            break;
        }
        let nonce = i.wrapping_mul(SCRAMBLE);
        t.scanned += 1;
        let h = hash_number_words(&mid.hash_words(nonce));
        let target = meets(&h, kt);
        t.target_hits += target as u64;
        let levels = filter_levels(ks, kt).map(|k| meets(&h, k));
        for (c, hit) in t.level_hits.iter_mut().zip(levels) {
            *c += hit as u64;
        }
        if let (Some(conds), Some(full)) = (conds, full_mask) {
            // Inner second-block compression: state entering round 4, a and e after it.
            let mut w = [0u32; 64];
            w[..16].copy_from_slice(&mid.second_block(nonce));
            let mut s = mid.state;
            for r in 0..4 {
                s = round(&s, K[r], w[r]);
            }
            let after = round(&s, K[4], w[4]);
            let snap = Snapshot { s: &s, w: &w, new_a: after[0], new_e: after[4] };
            if condition_mask(conds, &snap) == full {
                t.cond_scanned += 1;
                for (c, hit) in t.cond_level_hits.iter_mut().zip(levels) {
                    *c += hit as u64;
                }
            }
        }
        if meets(&h, ks) {
            t.share_hits += 1;
            for (j, (nm, flip)) in neighbours.iter().enumerate() {
                let n2 = nonce ^ flip;
                t.neighbour_target[j] += meets(&hash_number_words(&nm.hash_words(n2)), kt) as u64;
            }
        }
    }
    t
}

fn rate(k: u64, n: u64) -> Value {
    let (lo, hi) = wilson(k, n, Z95);
    json!({ "count": k, "of": n, "p": k as f64 / n.max(1) as f64, "ci95": [lo, hi] })
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let ks = p_u64(params, "k_share")? as u32;
    let kt = p_u64(params, "k_target")? as u32;
    anyhow::ensure!(ks >= 1 && ks <= kt && kt <= 32, "need 1 <= k_share <= k_target <= 32");
    let want = p_u64(params, "share_hits")?;
    let budget = p_u64(params, "trail_budget_bits")? as f64;
    let top = p_u64(params, "trail_top")? as usize;
    let vpairs = p_u64(params, "trail_validation_pairs")?;
    let alpha = crate::p_f64(params, "alpha")?;

    // ---- A. trail search over controllable differences -------------------
    let mut cands: Vec<Delta> = Vec::new();
    for b in 0..32 {
        cands.push(Delta { w0: 1 << b, w1: 0, w3: 0 });
        cands.push(Delta { w0: 0, w1: 1 << b, w3: 0 });
        cands.push(Delta { w0: 0, w1: 0, w3: 1 << b });
    }
    for a in 0..32 {
        for b in a + 1..32 {
            cands.push(Delta { w0: 0, w1: 0, w3: 1 << a | 1 << b });
        }
    }
    let mut ranked: Vec<(Delta, usize, f64)> = cands.iter().map(|d| { let (r, c) = reach(d, budget); (*d, r, c) }).collect();
    ranked.sort_by(|x, y| y.1.cmp(&x.1).then(y.2.total_cmp(&x.2)));
    let best: Vec<(Delta, usize, f64)> = ranked.iter().take(top).copied().collect();
    let validated: Vec<Value> = best
        .iter()
        .take(3)
        .map(|(d, r, c)| {
            let k = follow_rate(d, *r, vpairs, seed ^ 0x7a11);
            let (lo, hi) = wilson(k, vpairs, Z95);
            json!({ "delta": d.label(), "rounds": r, "signed_estimate_log2": c, "measured": rate(k, vpairs),
                    "estimate_inside_ci": (lo..=hi).contains(&2f64.powf(*c)) })
        })
        .collect();
    let trail_search = json!({
        "candidates": cands.len(),
        "budget_bits": budget,
        "top": best.iter().map(|(d, r, c)| json!({ "delta": d.label(), "rounds_within_budget": r, "signed_estimate_log2": c })).collect::<Vec<_>>(),
        "validated": validated,
        "max_rounds_reached": best.first().map(|b| b.1),
    });

    // ---- B and C. Bitcoin conditional target-hit probabilities -----------
    let mut deltas: Vec<Delta> = (0..32).map(|b| Delta { w0: 0, w1: 0, w3: 1 << b }).collect();
    for (d, _, _) in &best {
        if !deltas.contains(d) {
            deltas.push(*d);
        }
    }
    // Conditions of the nonce-MSB trail (W3 bit 31 enters at round 3; conditions at round 4).
    let msb = Delta { w0: 0, w1: 0, w3: 1 << 31 };
    let cond_trail = xor_trail(&msb.message(), 5);
    let conds = derive(&cond_trail, 4);
    let tests = rounds.len() * (deltas.len() + 2);
    let z_crit = statistical_engine::z_for_two_sided(alpha / tests as f64);
    let null = 0.5f64.powi(kt as i32);
    let headers = 64u64;
    let per_header = want.div_ceil(headers);
    let (mut obs, mut det, mut flags, mut summary) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for &r in &rounds {
        let t = (0..headers)
            .into_par_iter()
            .map(|h| {
                let mid = HeaderMidstate::with_rounds(&header(seed, h), r);
                let c = if r >= 5 { conds.as_deref() } else { None };
                // Cap at 16x the expected scan, so structure that makes shares rare cannot stall.
                scan_header(&mid, &deltas, c, ks, kt, per_header, per_header << (ks + 4))
            })
            .reduce(|| Tally::new(deltas.len()), Tally::add);
        let base = t.target_hits as f64 / t.scanned as f64;
        let per_delta: Vec<Value> = deltas
            .iter()
            .zip(&t.neighbour_target)
            .map(|(d, &k)| {
                let q = k as f64 / t.share_hits as f64;
                let z = binomial_z(k, t.share_hits, null);
                json!({ "delta": d.label(), "neighbour_target_hits": rate(k, t.share_hits), "amplification": q / null, "z": z, "significant": z.abs() > z_crit })
            })
            .collect();
        let neigh_hits: u64 = t.neighbour_target.iter().sum();
        let neigh_evals = t.share_hits * deltas.len() as u64;
        // Strategy 1 (exhaustive): fresh nonces. Strategy 2 (neighbours): scan, then also
        // evaluate every neighbour of each share hit. Both counted per target hit.
        let exhaustive = t.scanned as f64 / t.target_hits.max(1) as f64;
        let neighbour_cost = (t.scanned + neigh_evals) as f64 / (t.target_hits + neigh_hits).max(1) as f64;
        let neighbour_efficiency = rate(neigh_hits, neigh_evals);
        let nz = binomial_z(neigh_hits, neigh_evals, null);
        // Strategy 3 (condition filter): check 5 rounds for every nonce, hash only those passing.
        // A filter that keeps a fraction pc of nonces and multiplies the hit
        // rate by A costs (5/128 + pc) / (pc * A * 2^-k) per hit: it can only
        // pay off when A > 1 + 5/(128 pc), i.e. A must be large.
        let filter = conds.as_ref().filter(|_| r >= 5).map(|cs| {
            let pc = t.cond_scanned as f64 / t.scanned as f64;
            let levels: Vec<Value> = filter_levels(ks, kt)
                .iter()
                .enumerate()
                .map(|(j, &k)| {
                    let p0 = 0.5f64.powi(k as i32);
                    let (hc, hall) = (t.cond_level_hits[j], t.level_hits[j]);
                    let a = hc as f64 / t.cond_scanned.max(1) as f64 / p0;
                    let z = binomial_z(hc, t.cond_scanned, p0);
                    json!({
                        "zero_bits": k, "hits_given_conditions": rate(hc, t.cond_scanned), "hits_overall": rate(hall, t.scanned),
                        "amplification": a, "z": z, "significant": z.abs() > z_crit,
                        "break_even_amplification": 1.0 + 5.0 / 128.0 / pc,
                    })
                })
                .collect();
            json!({ "conditions": cs.len(), "p_conditions": rate(t.cond_scanned, t.scanned), "levels": levels })
        });
        let any_delta = per_delta.iter().any(|d| d["significant"] == true);
        let filt_sig = filter.as_ref().is_some_and(|f| f["levels"].as_array().is_some_and(|l| l.iter().any(|x| x["significant"] == true)));
        let deviation = any_delta || nz.abs() > z_crit || filt_sig;
        flags.push((r, deviation));
        det.push(json!([r, t.scanned, t.target_hits, t.share_hits, t.neighbour_target, t.cond_scanned, t.level_hits, t.cond_level_hits]));
        obs.push(json!({
            "rounds": r,
            "scanned": t.scanned,
            "target_rate": rate(t.target_hits, t.scanned),
            "target_rate_over_null": base / null,
            "share_hits": t.share_hits,
            "neighbours": per_delta,
            "neighbour_pooled": { "efficiency": neighbour_efficiency, "amplification": neigh_hits as f64 / neigh_evals as f64 / null, "z": nz },
            "condition_filter": filter,
            "expected_work_per_target_hit": {
                "exhaustive": exhaustive,
                "neighbour_strategy": neighbour_cost,
                "neighbour_over_exhaustive": neighbour_cost / exhaustive,
            },
            "z_critical": z_crit,
            "deviation_detected": deviation,
        }));
    }
    let full = obs.iter().find(|o| o["rounds"] == FULL_ROUNDS);
    summary.push(format!(
        "Trail search over {} controllable differences: best survives to round {} of the second header block within {budget} bits.",
        cands.len(), trail_search["max_rounds_reached"]
    ));
    if let Some(f) = full {
        let np = &f["neighbour_pooled"];
        let lv = &f["condition_filter"]["levels"];
        summary.push(format!(
            "Full SHA256d: neighbours of share hits hit the 2^-{kt} target at {:.4}x the null rate (z {:+.2}); the neighbour strategy needs {:.4}x the exhaustive work per hit. Inputs satisfying the 11 trail conditions hit {}-bit / {}-bit / {}-bit levels at {:.3}x / {:.3}x / {:.3}x the null rate.",
            np["amplification"].as_f64().unwrap_or(f64::NAN), np["z"].as_f64().unwrap_or(f64::NAN),
            f["expected_work_per_target_hit"]["neighbour_over_exhaustive"].as_f64().unwrap_or(f64::NAN),
            lv[0]["zero_bits"], lv[1]["zero_bits"], lv[2]["zero_bits"],
            lv[0]["amplification"].as_f64().unwrap_or(f64::NAN), lv[1]["amplification"].as_f64().unwrap_or(f64::NAN), lv[2]["amplification"].as_f64().unwrap_or(f64::NAN),
        ));
    }
    let dev: Vec<usize> = flags.iter().filter(|f| f.1).map(|f| f.0).collect();
    summary.push(format!("Round counts where some strategy beats the null rate: {dev:?}."));
    Ok(Outcome::new(json!({ "trail_search": trail_search, "target_search": obs, "neighbour_deltas": deltas.iter().map(Delta::label).collect::<Vec<_>>() }), json!({ "ranked": ranked.iter().take(top).map(|(d, r, c)| json!([d.label(), r, c])).collect::<Vec<_>>(), "scans": det }), flags, summary))
}

/// Recount the first headers' share hits and neighbour outcomes with the
/// independent SHA-256 over full serialized headers.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let ks = p_u64(params, "k_share")? as u32;
    let kt = p_u64(params, "k_target")? as u32;
    let ind = verification::independent::Sha256::default();
    let mut problems = Vec::new();
    let mut checked = 0u64;
    let words = |d: [u8; 32]| Target::from_hash(&d).words();
    for r in p_rounds(params)? {
        let mut h = header(seed, 0);
        let mid = HeaderMidstate::with_rounds(&h, r);
        let mut shares = 0;
        for i in 0u32..1 << 24 {
            if shares >= 64 {
                break;
            }
            let nonce = i.wrapping_mul(SCRAMBLE);
            h[76..80].copy_from_slice(&nonce.to_le_bytes());
            let a = words(ind.sha256d(&h, r));
            if a != hash_number_words(&mid.hash_words(nonce)) {
                problems.push(format!("r{r} nonce {nonce}: hash mismatch"));
                break;
            }
            if meets(&a, ks) {
                shares += 1;
                // Nonce-bit-0 neighbour, recomputed from the serialized header.
                let mut h2 = h;
                h2[76..80].copy_from_slice(&(nonce ^ 1u32.swap_bytes()).to_le_bytes());
                let b = words(ind.sha256d(&h2, r));
                let (m2, n2) = Delta { w0: 0, w1: 0, w3: 1 }.apply(&mid, nonce);
                if meets(&b, kt) != meets(&hash_number_words(&m2.hash_words(n2)), kt) {
                    problems.push(format!("r{r} nonce {nonce}: neighbour mismatch"));
                }
                checked += 1;
            }
        }
    }
    let validated_ok = outcome.observations["trail_search"]["validated"].as_array().is_some_and(|v| !v.is_empty());
    if !validated_ok {
        problems.push("no trail validated".into());
    }
    problems.truncate(10);
    Ok(Verification {
        method: "independent SHA-256 over the full serialized header recomputes scanned hashes and the W3-bit-0 neighbour of each share hit (first header, 64 share hits per round count)".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { format!("{checked} share hits and their neighbours identical") } else { problems.join("; ") },
    })
}
