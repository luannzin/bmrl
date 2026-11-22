//! Mainnet header atlas: every main-chain block header, validated with our
//! own consensus code and measured.
//!
//! * Chain: links, proof of work, every difficulty retarget and the
//!   median-time-past rule, recomputed here, plus known block hashes.
//! * Hash below target: a winning hash is the first one at or below the
//!   target, so if SHA256d behaves as a random function, hash / target is
//!   uniform on [0, 1] for every block. This is the largest real-world test of
//!   that property (each block stands for the network's whole search).
//! * Miner behaviour (descriptive, not a SHA-256 test): nonce bits per era,
//!   BIP320 version-rolling bits (overt AsicBoost) per year, timestamps.
//! * Economics: network hashrate over the last difficulty period and the
//!   expected subsidy per day of the devices this project measured.
//!
//! Data: `experiments/data/mainnet-headers.bin` (80 bytes per block, from
//! `bmr research sync-headers` over the P2P network, gitignored). The record
//! stores the analysed height and the SHA-256 of the analysed bytes.

use crate::{Definition, Outcome, Verification, p_u64};
use anyhow::{Context, Result, ensure};
use bitcoin_header::{BlockHeader, HEADER_LEN, MAINNET_POW_LIMIT_BITS, RETARGET_INTERVAL, Target, block_work, check_proof_of_work, fixtures, median_time_past, next_work_required, parse_display_hex};
use rayon::prelude::*;
use serde_json::{Value, json};
use statistical_engine::{chi_square_gof, ks_uniform};
use std::path::PathBuf;

/// Blocks below the tip that are not analysed (reorg margin).
pub const CONFIRMATIONS: u64 = 6;
const HALVING: u64 = 210_000;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-MAINNET-01",
        primitive: crate::primitive::HEADER,
        name: "Mainnet header atlas: chain validation, hash/target uniformity, miner behaviour, economics",
        version: 1,
        hypothesis: "Over every main-chain block, the winning hash divided by its target departs from Uniform(0, 1), i.e. real-world SHA256d mining shows structure below the target.",
        null_hypothesis: "hash / target is uniform on [0, 1] in every halving era, as for a random function.",
        assumptions: &[
            "Headers come from public P2P peers; nothing is trusted: links, proof of work, retargets and median time past are recomputed, and known block hashes are checked.",
            "The last 6 blocks below the downloaded tip are excluded (reorg margin).",
            "hash / target is computed in f64 from the 256-bit values (relative error about 1e-16).",
            "Nonce, version and time statistics describe miner software and hardware; they are not tests of SHA-256 and are never flagged as deviations.",
            "Economics: subsidy only (fees are not in headers); device rates are this project's measurements except the Bitaxe-class figure, a vendor specification.",
        ],
        baseline: "Uniform(0, 1) for hash / target; 1/2 for each nonce bit.",
        methodology: "Load headers 0..=height, validate every consensus rule on headers, compute u = hash / target per block, test u with Kolmogorov-Smirnov over all blocks and per halving era and with a 20-bin chi-square (Bonferroni over these tests at 0.001); describe nonce bits per era, version bits per year, timestamps; estimate hashrate from the last 2016 blocks.",
        implementation: &["experiment_engine::header_atlas", "mining_engine::p2p (download)", "bitcoin_header::{next_work_required, median_time_past, check_proof_of_work}"],
        dataset: "experiments/data/mainnet-headers.bin, heights 0..=params.height.",
    }
}

pub fn data_path() -> PathBuf {
    research_storage::workspace_root().join("experiments").join("data").join("mainnet-headers.bin")
}

/// Stored headers, genesis first; just the genesis header when nothing is stored.
pub fn load() -> Result<Vec<BlockHeader>> {
    let genesis = BlockHeader::from_hex(fixtures::MAINNET[0].header_hex).expect("fixture");
    let Ok(bytes) = std::fs::read(data_path()) else { return Ok(vec![genesis]) };
    ensure!(bytes.len() % HEADER_LEN == 0, "{} is not a whole number of headers", data_path().display());
    let chain: Vec<BlockHeader> = bytes.as_chunks::<HEADER_LEN>().0.iter().map(BlockHeader::deserialize).collect();
    ensure!(chain.first() == Some(&genesis), "stored headers do not start at the main-network genesis block");
    Ok(chain)
}

pub fn save(chain: &[BlockHeader]) -> Result<()> {
    let path = data_path();
    std::fs::create_dir_all(path.parent().expect("has a parent"))?;
    let bytes: Vec<u8> = chain.iter().flat_map(|h| h.serialize()).collect();
    std::fs::write(&path, bytes)?;
    Ok(())
}

pub fn default_params(_quick: bool) -> Value {
    let tip = load().map(|c| c.len() as u64 - 1).unwrap_or(0);
    json!({
        "height": tip.saturating_sub(CONFIRMATIONS),
        "devices": [
            { "name": "cpu-avx2 x28 (bench-cpu)", "hashes_per_second": 1.166e8 },
            { "name": "gpu v2 RX 7600 (bench-gpu-0006)", "hashes_per_second": 1.752e9 },
            { "name": "gpu v3 RX 7600 (bench-gpu-0006)", "hashes_per_second": 1.914e9 },
            { "name": "Bitaxe-class BM1370 board (vendor figure, not measured)", "hashes_per_second": 1.2e12 },
        ],
        "reproduce": true,
    })
}

/// hash / target in f64.
fn ratio(hash: &[u8; 32], bits: u32) -> f64 {
    let f = |b: &[u8; 32]| b.iter().fold(0.0f64, |a, &x| a * 256.0 + x as f64);
    f(&Target::from_hash(hash).0) / f(&Target::from_compact(bits).target.0)
}

fn era(h: usize) -> usize {
    (h as u64 / HALVING) as usize
}

/// Year (UTC) of a Unix time, by the civil-from-days algorithm.
fn year(t: u32) -> i64 {
    let z = t as i64 / 86_400 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + i64::from(mp >= 10)
}

struct Validation {
    link: usize,
    pow: usize,
    bits: usize,
    mtp: usize,
    first_failures: Vec<Value>,
}

fn validate(chain: &[BlockHeader], hashes: &[[u8; 32]]) -> Validation {
    let mut v = Validation { link: 0, pow: 0, bits: 0, mtp: 0, first_failures: vec![] };
    let fail = |v: &mut Validation, rule: &str, h: usize| {
        if v.first_failures.len() < 10 {
            v.first_failures.push(json!({ "rule": rule, "height": h }));
        }
    };
    for h in 0..chain.len() {
        let hd = &chain[h];
        if check_proof_of_work(&hashes[h], hd.bits, MAINNET_POW_LIMIT_BITS) != Ok(true) {
            v.pow += 1;
            fail(&mut v, "proof-of-work", h);
        }
        if h == 0 {
            continue;
        }
        if hd.prev_blockhash != hashes[h - 1] {
            v.link += 1;
            fail(&mut v, "link", h);
        }
        let want = if h % RETARGET_INTERVAL == 0 {
            next_work_required(chain[h - 1].bits, chain[h - RETARGET_INTERVAL].time, chain[h - 1].time, MAINNET_POW_LIMIT_BITS)
        } else {
            chain[h - 1].bits
        };
        if hd.bits != want {
            v.bits += 1;
            fail(&mut v, "difficulty", h);
        }
        let times: Vec<u32> = chain[h.saturating_sub(11)..h].iter().map(|x| x.time).collect();
        if hd.time <= median_time_past(&times) {
            v.mtp += 1;
            fail(&mut v, "median-time-past", h);
        }
    }
    v
}

pub fn execute(params: &Value, _seed: u64) -> Result<Outcome> {
    let height = p_u64(params, "height")? as usize;
    let all = load()?;
    ensure!(all.len() > height && height > 0, "headers stored up to {} but height {height} requested: run `bmr research sync-headers` first", all.len() - 1);
    let chain = &all[..=height];
    let hashes: Vec<[u8; 32]> = chain.par_iter().map(BlockHeader::hash).collect();
    let bytes: Vec<u8> = chain.iter().flat_map(|h| h.serialize()).collect();
    let data_sha256 = bitcoin_header::hex_encode(&sha256_core::sha256(&bytes));

    // Chain validation and known hashes.
    let val = validate(chain, &hashes);
    let mut known = vec![(0usize, fixtures::MAINNET[0].hash), (1, fixtures::MAINNET[1].hash), (100_000, fixtures::BLOCK_100000_HASH), (125_552, fixtures::MAINNET[2].hash)];
    known.retain(|&(h, _)| h <= height);
    let known_ok = known.iter().all(|&(h, hex)| parse_display_hex(hex).is_ok_and(|x| x == hashes[h]));
    let chain_ok = val.link + val.pow + val.bits + val.mtp == 0 && known_ok;
    let total_work: f64 = chain.iter().map(|h| block_work(h.bits)).sum();

    // hash / target.
    let u: Vec<f64> = (1..=height).map(|h| ratio(&hashes[h], chain[h].bits)).collect();
    let eras = era(height) + 1;
    let mut tests = Vec::new();
    let (d, p) = ks_uniform(&u);
    tests.push(json!({ "test": "KS all blocks", "n": u.len(), "d": d, "p": p }));
    for e in 0..eras {
        let ue: Vec<f64> = (1..=height).filter(|&h| era(h) == e).map(|h| u[h - 1]).collect();
        let (d, p) = ks_uniform(&ue);
        tests.push(json!({ "test": format!("KS era {e} (heights {}..)", e as u64 * HALVING), "n": ue.len(), "d": d, "p": p }));
    }
    let mut bins = [0u64; 20];
    for &x in &u {
        bins[((x * 20.0) as usize).min(19)] += 1;
    }
    let chi = chi_square_gof(&bins, &[0.05; 20]);
    tests.push(json!({ "test": "chi-square 20 bins", "n": u.len(), "statistic": chi.statistic, "df": chi.df, "p": chi.p_value }));
    let threshold = 0.001 / tests.len() as f64;
    let deviation = tests.iter().any(|t| t["p"].as_f64().unwrap_or(1.0) < threshold);
    let (luck_h, luck_u) = u.iter().enumerate().min_by(|a, b| a.1.total_cmp(b.1)).map(|(i, &x)| (i + 1, x)).unwrap_or((0, 1.0));

    // Nonce bits per era (descriptive).
    let nonce_eras: Vec<Value> = (0..eras)
        .map(|e| {
            let hs: Vec<usize> = (1..=height).filter(|&h| era(h) == e).collect();
            let n = hs.len() as f64;
            let z: Vec<f64> = (0..32)
                .map(|b| {
                    let ones = hs.iter().filter(|&&h| chain[h].nonce >> b & 1 == 1).count() as f64;
                    (ones - n / 2.0) / (n / 4.0).sqrt()
                })
                .collect();
            let mut top = [0u64; 256];
            for &h in &hs {
                top[(chain[h].nonce >> 24) as usize] += 1;
            }
            let top_chi = chi_square_gof(&top, &[1.0 / 256.0; 256]);
            let worst = (0..32).max_by(|&a, &b| z[a].abs().total_cmp(&z[b].abs())).unwrap_or(0);
            json!({ "era": e, "blocks": hs.len(), "bit_z": z, "max_abs_z_bit": worst, "max_abs_z": z[worst],
                    "sum_z2_32_bits": z.iter().map(|x| x * x).sum::<f64>(), "top_byte_chi2_p": top_chi.p_value })
        })
        .collect();

    // Version bits per year (descriptive).
    let mut years: std::collections::BTreeMap<i64, (u64, u64, u64)> = Default::default();
    for hd in &chain[1..] {
        let y = years.entry(year(hd.time)).or_default();
        y.0 += 1;
        y.1 += u64::from(hd.version as u32 & 0x1fff_e000 != 0 && hd.version as u32 >> 29 == 1);
        y.2 += u64::from(hd.version as u32 >> 29 == 1);
    }
    let version_years: Vec<Value> = years
        .iter()
        .map(|(y, &(n, rolled, bip9))| json!({ "year": y, "blocks": n, "bip320_bits_set": rolled as f64 / n as f64, "bip9_top_bits": bip9 as f64 / n as f64 }))
        .collect();

    // Timestamps (descriptive).
    let backwards = (1..=height).filter(|&h| chain[h].time < chain[h - 1].time).count();
    let mean_interval = (chain[height].time as f64 - chain[0].time as f64) / height as f64;

    // Economics over the last difficulty period.
    let first = height.saturating_sub(RETARGET_INTERVAL);
    let span = (chain[height].time as f64 - chain[first].time as f64).max(1.0);
    let period_work: f64 = chain[first + 1..=height].iter().map(|h| block_work(h.bits)).sum();
    let hashrate = period_work / span;
    let subsidy_sats = (50u64 * 100_000_000) >> (height as u64 / HALVING).min(63);
    let blocks_per_day = 86_400.0 / 600.0;
    let devices: Vec<Value> = params["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|d| {
            let r = d["hashes_per_second"].as_f64().unwrap_or(0.0);
            let share = r / hashrate;
            let per_day = share * blocks_per_day;
            json!({ "device": d["name"], "hashes_per_second": r, "network_share": share,
                    "expected_sats_per_day": per_day * subsidy_sats as f64, "expected_years_per_block": 1.0 / (per_day * 365.25),
                    "p_block_within_a_year": 1.0 - (-per_day * 365.25).exp() })
        })
        .collect();

    let mut summary = vec![
        format!("{} main-chain headers (heights 0..={height}, data sha256 {}), validated here: {} link, {} proof-of-work, {} difficulty and {} median-time-past failures; known hashes {}; total work 2^{:.2}.",
            height + 1, &data_sha256[..16], val.link, val.pow, val.bits, val.mtp, if known_ok { "match" } else { "MISMATCH" }, total_work.log2()),
        format!("hash / target over {} blocks: KS p = {:.3}, 20-bin chi-square p = {:.3}; per-era KS p {}; Bonferroni threshold {threshold:.1e}: {}.",
            u.len(), tests[0]["p"].as_f64().unwrap_or(1.0), chi.p_value,
            tests[1..eras + 1].iter().map(|t| format!("{:.3}", t["p"].as_f64().unwrap_or(1.0))).collect::<Vec<_>>().join(", "),
            if deviation { "DEVIATION" } else { "consistent with a random function" }),
        format!("Luckiest block: height {luck_h}, hash = {:.3e} x target ({:.1} extra zero bits).", luck_u, -luck_u.log2()),
        format!("Miner behaviour (not SHA-256): nonce-bit max |z| per era {}; BIP320 version-rolling bits in {:.1}% of the last year's blocks; {backwards} blocks earlier than their parent; mean interval {mean_interval:.1} s.",
            nonce_eras.iter().map(|e| format!("{:.1} (bit {})", e["max_abs_z"].as_f64().unwrap_or(0.0).abs(), e["max_abs_z_bit"])).collect::<Vec<_>>().join(", "),
            100.0 * version_years.last().and_then(|y| y["bip320_bits_set"].as_f64()).unwrap_or(0.0)),
        format!("Network hashrate over the last 2016 blocks: {:.3e} H/s; subsidy {} sats. {}", hashrate, subsidy_sats,
            devices.iter().map(|d| format!("{}: {:.3e} sats/day, one block per {:.3e} years", d["device"].as_str().unwrap_or(""), d["expected_sats_per_day"].as_f64().unwrap_or(0.0), d["expected_years_per_block"].as_f64().unwrap_or(0.0))).collect::<Vec<_>>().join("; ")),
    ];
    if !chain_ok {
        summary.push("CHAIN VALIDATION FAILED: the statistics above are not trustworthy.".into());
    }
    let obs = json!({
        "height": height, "tip_hash": bitcoin_header::display_hex(&hashes[height]), "data_sha256": data_sha256,
        "validation": { "link_failures": val.link, "pow_failures": val.pow, "difficulty_failures": val.bits, "mtp_failures": val.mtp,
                        "first_failures": val.first_failures, "known_hashes_checked": known.len(), "known_hashes_match": known_ok, "passed": chain_ok,
                        "total_work_log2": total_work.log2() },
        "hash_over_target": { "tests": tests, "bonferroni_threshold": threshold, "deviation": deviation, "luckiest": { "height": luck_h, "ratio": luck_u } },
        "nonce_by_era": nonce_eras,
        "version_by_year": version_years,
        "time": { "blocks_before_parent": backwards, "mean_interval_seconds": mean_interval },
        "economics": { "period_first_height": first, "network_hashes_per_second": hashrate, "subsidy_sats": subsidy_sats, "fees": "not included (not in headers)", "devices": devices },
    });
    let mut o = Outcome::new(obs.clone(), obs, vec![(crate::FULL_ROUNDS, deviation)], summary);
    if !chain_ok {
        o.result = Some("error");
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    #[test]
    fn year_of_unix_time() {
        assert_eq!(super::year(1_231_006_505), 2009); // genesis
        assert_eq!(super::year(1_735_689_600), 2025); // 2025-01-01T00:00:00Z
        assert_eq!(super::year(1_735_689_599), 2024);
    }
}

/// Recompute block hashes with the independent SHA-256 on a sample, and the
/// hash / target ratio from integer comparison for the luckiest block.
pub fn verify(params: &Value, _seed: u64, outcome: &Outcome) -> Result<Verification> {
    let height = p_u64(params, "height")? as usize;
    let chain = load()?;
    let mut problems = Vec::new();
    if outcome.observations["validation"]["passed"] != true {
        problems.push("chain validation failed".to_string());
    }
    for h in (0..=height).step_by((height / 4096).max(1)) {
        let ours = chain[h].hash();
        let theirs = verification::third_party_sha256d(&chain[h].serialize());
        if ours != theirs {
            problems.push(format!("hash mismatch at {h}"));
            break;
        }
        if h > 0 && chain[h].prev_blockhash != chain[h - 1].hash() {
            problems.push(format!("link mismatch at {h}"));
            break;
        }
    }
    let lucky = outcome.observations["hash_over_target"]["luckiest"]["height"].as_u64().context("no luckiest block")? as usize;
    let hash = Target::from_hash(&chain[lucky].hash());
    if hash > Target::from_compact(chain[lucky].bits).target {
        problems.push("luckiest block does not meet its target".into());
    }
    Ok(Verification {
        method: "block hashes of every (height/4096)-th header recomputed with the sha2 crate and links rechecked; the luckiest block's hash compared with its target as 256-bit integers".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "independent hashes, links and target comparison agree".into() } else { problems.join("; ") },
    })
}
