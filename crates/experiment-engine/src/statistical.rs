//! Statistical tests on the actual mining function: SHA-256d of 80-byte block
//! headers as a function of the nonce, at full and reduced round counts.
//!
//! The mining-relevant question is whether some nonces (or nonce neighbours)
//! meet a target more often than 2^-k. Bit frequencies, the leading-zero
//! distribution and consecutive-nonce bit agreement are tested.

use crate::{Definition, Outcome, Verification, p_f64, p_rounds, p_u64};
use anyhow::Result;
use bitcoin_header::{HeaderMidstate, Target, hash_number_words};
use rayon::prelude::*;
use serde_json::{Value, json};
use statistical_engine::{SplitMix64, Z95, binomial_half_pmf, binomial_z, chi_square_gof, two_sided_p, wilson};
use verification::independent;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-STAT-01",
        primitive: crate::primitive::HEADER,
        name: "Statistical uniformity of SHA-256d block-header hashes over the nonce",
        version: 1,
        hypothesis: "As a function of the 32-bit nonce, r-round SHA-256d of an 80-byte header shows a measurable deviation from uniform output: biased output bits, a leading-zero distribution that departs from P(lz = k) = 2^-(k+1) (which would change the expected work per block), or correlation between hashes of consecutive nonces.",
        null_hypothesis: "Hash numbers of distinct nonces are independent and uniform on [0, 2^256).",
        assumptions: &[
            "Headers are 80 uniform random bytes (the nonce field is overwritten); real headers fix most fields, which only narrows the input set further.",
            "Hash read as Bitcoin's little-endian 256-bit number; 'leading zeros' counts from its most significant bit.",
            "Bit tests: binomial z with Bonferroni over 256 bits, 3 tests and all round counts.",
            "Chi-square tests with bins merged to expected count >= 5.",
            "Round-reduced variants cut all three compression calls to r rounds; midstate kept.",
        ],
        baseline: "Uniform random 256-bit outputs: each bit P(1) = 1/2; P(lz >= k) = 2^-k; bit agreement of consecutive hashes ~ Binomial(256, 1/2).",
        methodology: "For each round count, hash `nonces_per_header` consecutive nonces (from 0) for each of `headers` random headers. Accumulate per-bit one counts, the leading-zero histogram and the agreement histogram between hash(n) and hash(n+1). Report the observed rate of meeting 8- and 16-bit targets with Wilson intervals against 2^-k.",
        implementation: &["bitcoin_header::HeaderMidstate::with_rounds", "bitcoin_header::hash_number_words", "statistical_engine"],
        dataset: "`headers` random 80-byte headers from SplitMix64::stream(seed, header_index); nonces 0..nonces_per_header for each.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": [8, 12, 16, 20, 64],
        "headers": 64,
        "nonces_per_header": if quick { 4096 } else { 65536 },
        "alpha": 0.01,
        "reproduce": true,
    })
}

/// Running statistics of a stream of 256-bit hash numbers.
#[derive(Clone)]
pub(crate) struct Counts {
    pub ones: Vec<u64>,
    pub lz: Vec<u64>,
    pub agree: Vec<u64>,
    prev: Option<[u32; 8]>,
}

impl Counts {
    pub fn new() -> Self {
        Self { ones: vec![0; 256], lz: vec![0; 257], agree: vec![0; 257], prev: None }
    }

    pub fn add(mut self, o: Counts) -> Self {
        for (a, b) in [(&mut self.ones, &o.ones), (&mut self.lz, &o.lz), (&mut self.agree, &o.agree)] {
            a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
        }
        self.prev = None;
        self
    }

    /// Start a new sequence: the next value has no predecessor.
    pub fn restart(&mut self) {
        self.prev = None;
    }

    /// Record one hash number (most significant word first).
    pub fn observe(&mut self, n: [u32; 8]) {
        for (wi, w) in n.iter().enumerate() {
            let mut x = *w;
            while x != 0 {
                // Bit index 0 = most significant bit of the hash number.
                self.ones[wi * 32 + 31 - x.trailing_zeros() as usize] += 1;
                x &= x - 1;
            }
        }
        self.lz[leading_zeros(&n)] += 1;
        if let Some(p) = self.prev {
            let diff: u32 = p.iter().zip(&n).map(|(a, b)| (a ^ b).count_ones()).sum();
            self.agree[256 - diff as usize] += 1;
        }
        self.prev = Some(n);
    }

    pub fn hashes(&self) -> u64 {
        self.lz.iter().sum()
    }

    /// (Šidák-adjusted min bit p, leading-zero chi-square p, agreement chi-square p).
    pub fn p_values(&self) -> (f64, f64, f64) {
        let n = self.hashes();
        let pmin = self.ones.iter().map(|&k| two_sided_p(binomial_z(k, n, 0.5))).fold(1.0, f64::min);
        let sidak = -(256.0 * (-pmin).ln_1p()).exp_m1();
        let mut lz_probs: Vec<f64> = (0..256).map(|k| 0.5f64.powi(k + 1)).collect();
        lz_probs.push(0.5f64.powi(256));
        (sidak, chi_square_gof(&self.lz, &lz_probs).p_value, chi_square_gof(&self.agree, &binomial_half_pmf(256)).p_value)
    }
}

fn header(seed: u64, index: u64) -> [u8; 80] {
    SplitMix64::stream(seed, index).bytes()
}

fn leading_zeros(n: &[u32; 8]) -> usize {
    let mut z = 0;
    for w in n {
        z += w.leading_zeros() as usize;
        if *w != 0 {
            break;
        }
    }
    z
}

fn count(rounds: usize, seed: u64, headers: u64, per: u64) -> Counts {
    (0..headers)
        .into_par_iter()
        .map(|h| {
            let mid = HeaderMidstate::with_rounds(&header(seed, h), rounds);
            let mut c = Counts::new();
            for nonce in 0..per {
                c.observe(hash_number_words(&mid.hash_words(nonce as u32)));
            }
            c
        })
        .reduce(Counts::new, Counts::add)
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let headers = p_u64(params, "headers")?;
    let per = p_u64(params, "nonces_per_header")?.min(1 << 32);
    let alpha = p_f64(params, "alpha")?;
    let alpha_test = alpha / (rounds.len() * 3) as f64;
    let n = headers * per;
    let mut lz_probs: Vec<f64> = (0..256).map(|k| 0.5f64.powi(k + 1)).collect();
    lz_probs.push(0.5f64.powi(256));
    let agree_probs = binomial_half_pmf(256);
    let (mut obs, mut det, mut flags) = (Vec::new(), Vec::new(), Vec::new());
    for &r in &rounds {
        let c = count(r, seed, headers, per);
        let zs: Vec<f64> = c.ones.iter().map(|&k| binomial_z(k, n, 0.5)).collect();
        let (worst, max_z) = zs.iter().enumerate().fold((0, 0.0f64), |acc, (i, z)| if z.abs() > acc.1 { (i, z.abs()) } else { acc });
        let significant_bits = zs.iter().filter(|z| two_sided_p(**z) < alpha_test / 256.0).count();
        let lz_gof = chi_square_gof(&c.lz, &lz_probs);
        let agree_gof = chi_square_gof(&c.agree, &agree_probs);
        let deviation = significant_bits > 0 || lz_gof.p_value < alpha_test || agree_gof.p_value < alpha_test;
        flags.push((r, deviation));
        let target_rates: Vec<Value> = [8usize, 16, 20]
            .iter()
            .map(|&k| {
                let hits: u64 = c.lz[k..].iter().sum();
                let expected = 0.5f64.powi(k as i32);
                json!({
                    "zero_bits": k,
                    "hits": hits,
                    "observed_rate": hits as f64 / n as f64,
                    "expected_rate": expected,
                    "ci95": wilson(hits, n, Z95),
                    "observed_over_expected": hits as f64 / n as f64 / expected,
                })
            })
            .collect();
        det.push(json!({ "rounds": r, "ones": c.ones, "lz": c.lz, "agree": c.agree }));
        obs.push(json!({
            "rounds": r,
            "hashes": n,
            "bit_frequency": {
                "max_abs_z": max_z,
                "worst_bit_from_msb": worst,
                "worst_bit_p_one": c.ones[worst] as f64 / n as f64,
                "worst_bit_ci95": wilson(c.ones[worst], n, Z95),
                "bonferroni_significant_bits": significant_bits,
            },
            "leading_zeros_chi_square": { "statistic": lz_gof.statistic, "df": lz_gof.df, "p_value": lz_gof.p_value },
            "max_leading_zeros": c.lz.iter().rposition(|&x| x > 0),
            "target_hit_rates": target_rates,
            "consecutive_nonce_agreement_chi_square": { "statistic": agree_gof.statistic, "df": agree_gof.df, "p_value": agree_gof.p_value },
            "alpha_per_test": alpha_test,
            "deviation_detected": deviation,
        }));
    }
    let full = obs.iter().find(|o| o["rounds"] == 64);
    let mut summary = vec![format!("{n} header hashes per round count ({headers} headers x {per} nonces).")];
    if let Some(f) = full {
        let t = &f["target_hit_rates"][0];
        summary.push(format!(
            "Full SHA-256d: 8-bit target hit rate {:.6} vs expected {:.6} (95% CI {:.6}..{:.6}).",
            t["observed_rate"].as_f64().unwrap_or(0.0),
            t["expected_rate"].as_f64().unwrap_or(0.0),
            t["ci95"][0].as_f64().unwrap_or(0.0),
            t["ci95"][1].as_f64().unwrap_or(0.0)
        ));
    }
    let hit: Vec<usize> = flags.iter().filter(|f| f.1).map(|f| f.0).collect();
    summary.push(format!("Round counts with a detected deviation: {hit:?}."));
    Ok(Outcome::new(json!(obs), json!(det), flags, summary))
}

/// Recompute hashes of the first header from the full 80 bytes (no midstate)
/// with the independent SHA-256 and compare with the midstate path.
pub fn verify(params: &Value, seed: u64, _: &Outcome) -> Result<Verification> {
    let rounds = p_rounds(params)?;
    let per = p_u64(params, "nonces_per_header")?.min(2048);
    let ind = independent::Sha256::default();
    let mut mismatched = Vec::new();
    for &r in &rounds {
        let mut h = header(seed, 0);
        let mid = HeaderMidstate::with_rounds(&h, r);
        let bad = (0..per as u32).any(|nonce| {
            h[76..80].copy_from_slice(&nonce.to_le_bytes());
            Target::from_hash(&ind.sha256d(&h, r)).words() != hash_number_words(&mid.hash_words(nonce))
        });
        if bad {
            mismatched.push(r);
        }
    }
    Ok(Verification {
        method: "independent SHA-256 over the full serialized header (no midstate) for the first header's first nonces at every round count".into(),
        passed: mismatched.is_empty(),
        detail: format!("{per} nonces x {} round counts; mismatching round counts: {mismatched:?}", rounds.len()),
    })
}
