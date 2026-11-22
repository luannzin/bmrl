//! Exhaustive nonce-space atlas of SHA256d(header) for fixed block templates.
//!
//! For one template (merkle root, time, version fixed) the miner's inner
//! search space is the 2^32 nonce values. The sampling tests (statistical,
//! multiseed) look at a few million of them; this experiment evaluates every
//! one, at full rounds and at reduced round counts as positive controls.
//!
//! Per template it measures, exactly:
//! * random-function statistics of nonce -> top hash word (the most
//!   significant 32 bits of Bitcoin's hash number): image size and the number
//!   of nonces mapping to 0 (a 32-bit share target);
//! * the leading-zero distribution of the 256-bit hash number;
//! * cube sums: the XOR of all 256 output bits over the whole nonce cube and
//!   over each half with one nonce bit fixed to 0 (degree tests in the nonce
//!   variables), and the zero-bit rate of every aligned low-bit sub-cube of
//!   dimension >= 8.
//!
//! Then every input-selection strategy of these families is scored against
//! the share event "hash number has >= k_store leading zero bits":
//! fixed-bit subspaces (1 and 2 bits), every linear half-space over two
//! 24-bit projections of the nonce (Walsh-Hadamard transform), nonce byte
//! classes, Hamming-weight classes, XOR and modular nonce neighbours, and
//! every one of the 2^32 - 1 XOR and modular differences among the hits at
//! k_pair bits. Each family's winners are chosen on discovery templates and
//! re-measured on held-out templates; the work factor reported is the
//! held-out one.

use crate::{Definition, FULL_ROUNDS, Outcome, Verification, digest, p_f64, p_rounds, p_u64};
use anyhow::{Result, ensure};
use bitcoin_header::{BlockHeader, HeaderMidstate, Target, fixtures, parse_display_hex};
use cpu_backend::Prepared;
use mining_engine::Work;
use rayon::prelude::*;
use serde_json::{Value, json};
use statistical_engine::{SplitMix64, Z95, chi2_sf, erfc, gamma_q, two_sided_p};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-ATLAS-01",
        primitive: crate::primitive::HEADER,
        name: "Exhaustive nonce-space atlas: random-function tests and every input-selection strategy",
        version: 1,
        hypothesis: "For a fixed block template, the map nonce -> SHA256d(header) over all 2^32 nonces departs from a random function, or some input-selection strategy (fixed-bit subspace, linear half-space, byte class, Hamming class, nonce neighbour or nonce difference) selects nonces whose hash meets a share target more often than 2^-k, on held-out templates.",
        null_hypothesis: "Every random-function statistic matches its exact expectation, and every strategy's held-out hit rate equals 2^-k: no selection rule computed without SHA256d raises P(hash <= target) per evaluation.",
        assumptions: &[
            "Template = 80-byte header with the nonce field enumerated. Real templates are mainnet blocks 0, 1, 100000 and 125552; synthetic ones have a BIP320 version, a previous hash with 80 leading zero bits, a random merkle root, a 2023-2026 time and a 0x17 difficulty exponent.",
            "Real templates contain a known block-level hit, so their count of top-word zeros is size-biased (1 + Poisson); they are excluded from that test and serve as positive controls.",
            "A hit at k bits means the hash, read as Bitcoin's 256-bit number, has >= k leading zero bits: the real target comparison for a target of that form.",
            "Random-function expectations: image size and zero-preimage counts of n balls in 2^32 bins (exact moments); cube sums and sub-cube zero bits uniform; hits in a class of fraction f binomial.",
            "Discovery templates choose each family's best strategy; held-out templates measure it once. A family is flagged only when the discovery maximum (Bonferroni over the family) and the held-out test are both significant.",
            "Reduced-round variants cut all three compressions to r rounds; they are positive controls, never evidence about 64 rounds.",
            "Significance: Bonferroni over every p-value of every round count.",
        ],
        baseline: "Exhaustive search: every nonce costs one SHA256d evaluation and hits with probability 2^-k, so a strategy with held-out amplification A needs 1/A of the exhaustive work per hit.",
        methodology: "Enumerate all 2^nonce_bits nonces of each template with an 8-lane AVX2 evaluator; accumulate a 2^32-bit image bitmap, top-word zeros, the leading-zero histogram, a binary XOR tree over the nonce index (sub-cube sums and halves) and the hit list. Score all strategies on discovery templates, then the selected ones on held-out templates.",
        implementation: &["experiment_engine::nonce_atlas", "cpu_backend::Prepared::hash8", "bitcoin_header::HeaderMidstate::with_rounds"],
        dataset: "Synthetic template i: SplitMix64::stream(seed ^ 0xa71a5, i). The same synthetic templates are used at every round count. Discovery = first half of the synthetic templates, held-out = second half plus the real templates.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": [4, 5, 6, 8, 64],
        "nonce_bits": if quick { 20 } else { 32 },
        "synthetic_templates": if quick { 4 } else { 12 },
        "reduced_templates": if quick { 2 } else { 4 },
        "real_templates": !quick,
        "k_store": if quick { 6 } else { 16 },
        "k_pair": if quick { 8 } else { 18 },
        "modular_neighbours": 1024,
        "alpha": 0.01,
        "reproduce": true,
    })
}

/// Smallest sub-cube dimension whose zero-bit rate is recorded.
const LEVEL_MIN: usize = 8;
/// Nonces per parallel work item (and levels of the per-chunk XOR tree).
const CHUNK_BITS: usize = 16;
/// Width of the Walsh-Hadamard projections.
const PROJ_BITS: usize = 24;

type Words = [u32; 8];

fn xor(a: Words, b: Words) -> Words {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Binary-counter XOR tree over 2^levels outputs pushed in index order. The
/// aligned block of 2^j outputs at index k is one node at level j (a
/// j-dimensional sub-cube over the low index bits); `half[j]` is the XOR of
/// all outputs whose index bit j is 0 (the even nodes at level j).
struct Tree {
    levels: usize,
    record_min: usize,
    stack: Vec<Words>,
    half: Vec<Words>,
    /// Zero output bits summed over the nodes of each level, per word.
    zero_bits: Vec<[u64; 8]>,
    /// Per output bit (word * 32 + bit): zero count over the nodes of level `record_min`.
    bit_zeros: Vec<u64>,
    root: Words,
}

impl Tree {
    fn new(levels: usize, record_min: usize) -> Self {
        Self { levels, record_min, stack: vec![[0; 8]; levels], half: vec![[0; 8]; levels], zero_bits: vec![[0; 8]; levels + 1], bit_zeros: vec![0; 256], root: [0; 8] }
    }

    fn push(&mut self, index: u64, v: Words) {
        let (mut node, mut j, mut k) = (v, 0, index);
        loop {
            if j >= self.record_min {
                for (z, w) in self.zero_bits[j].iter_mut().zip(node) {
                    *z += w.count_zeros() as u64;
                }
            }
            if j == self.record_min {
                for (w, word) in node.iter().enumerate() {
                    let mut z = !word;
                    while z != 0 {
                        self.bit_zeros[w * 32 + z.trailing_zeros() as usize] += 1;
                        z &= z - 1;
                    }
                }
            }
            if j == self.levels {
                self.root = node;
                return;
            }
            if k & 1 == 0 {
                self.half[j] = xor(self.half[j], node);
                self.stack[j] = node;
                return;
            }
            node = xor(self.stack[j], node);
            j += 1;
            k >>= 1;
        }
    }
}

/// Everything measured on one template.
struct Map {
    n: u64,
    image: u64,
    zero_pre: Vec<u32>,
    /// Count of nonces by leading zero bits of the hash number (64 = ">= 64").
    lz: [u64; 65],
    cube_all: Words,
    /// Per nonce bit b: XOR of the outputs of all nonces with bit b = 0.
    half: Vec<Words>,
    /// Per sub-cube dimension j (index j): zero output bits over all nodes, per word.
    zero_bits: Vec<[u64; 8]>,
    /// Per output bit: zero sums over the sub-cubes of dimension LEVEL_MIN.
    bit_zeros: Vec<u64>,
    /// (nonce, leading zeros) with >= k_store zeros, sorted by nonce.
    hits: Vec<(u32, u8)>,
}

struct ChunkAcc {
    lz: [u64; 65],
    half: Vec<Words>,
    zero_bits: Vec<[u64; 8]>,
    bit_zeros: Vec<u64>,
    hits: Vec<(u32, u8)>,
    zero_pre: Vec<u32>,
}

impl ChunkAcc {
    fn empty(levels: usize) -> Self {
        Self { lz: [0; 65], half: vec![[0; 8]; levels], zero_bits: vec![[0; 8]; levels + 1], bit_zeros: vec![0; 256], hits: vec![], zero_pre: vec![] }
    }

    fn merge(mut self, o: ChunkAcc) -> Self {
        self.lz.iter_mut().zip(o.lz).for_each(|(a, b)| *a += b);
        self.half.iter_mut().zip(o.half).for_each(|(a, b)| *a = xor(*a, b));
        for (a, b) in self.zero_bits.iter_mut().zip(o.zero_bits) {
            a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
        }
        self.bit_zeros.iter_mut().zip(o.bit_zeros).for_each(|(a, b)| *a += b);
        self.hits.extend(o.hits);
        self.zero_pre.extend(o.zero_pre);
        self
    }
}

/// Leading zero bits of Bitcoin's hash number (capped at 64) from output state words.
fn leading_zeros(h: &Words) -> u32 {
    let (w0, w1) = (h[7].swap_bytes(), h[6].swap_bytes());
    if w0 != 0 {
        w0.leading_zeros()
    } else if w1 != 0 {
        32 + w1.leading_zeros()
    } else {
        64
    }
}

/// Evaluate every nonce in `0..2^nonce_bits` of one template.
fn enumerate(p: &Prepared, nonce_bits: usize, k_store: u32) -> Map {
    let chunk_bits = CHUNK_BITS.min(nonce_bits);
    let chunks = 1usize << (nonce_bits - chunk_bits);
    let bitmap: Vec<AtomicU64> = (0..1usize << 26).map(|_| AtomicU64::new(0)).collect();
    let mut roots = vec![[0u32; 8]; chunks];
    let acc = roots
        .par_iter_mut()
        .enumerate()
        .map(|(c, root)| {
            let base = (c << chunk_bits) as u32;
            let mut tree = Tree::new(chunk_bits, LEVEL_MIN);
            let mut a = ChunkAcc::empty(chunk_bits);
            for g in 0..1u32 << (chunk_bits - 3) {
                let out = p.hash8(base + 8 * g);
                for lane in 0..8u32 {
                    let h: Words = std::array::from_fn(|w| out[w][lane as usize]);
                    let nonce = base + 8 * g + lane;
                    let top = h[7].swap_bytes();
                    bitmap[(top >> 6) as usize].fetch_or(1 << (top & 63), Relaxed);
                    let lz = leading_zeros(&h);
                    a.lz[lz as usize] += 1;
                    if top == 0 {
                        a.zero_pre.push(nonce);
                    }
                    if lz >= k_store {
                        a.hits.push((nonce, lz as u8));
                    }
                    tree.push((8 * g + lane) as u64, h);
                }
            }
            *root = tree.root;
            a.half = tree.half;
            a.zero_bits = tree.zero_bits;
            a.bit_zeros = tree.bit_zeros;
            a
        })
        .reduce(|| ChunkAcc::empty(chunk_bits), ChunkAcc::merge);
    // Levels above the chunk: a second tree over the chunk roots.
    let mut upper = Tree::new(nonce_bits - chunk_bits, 1);
    for (c, r) in roots.iter().enumerate() {
        upper.push(c as u64, *r);
    }
    let mut zero_bits = acc.zero_bits;
    zero_bits.extend(upper.zero_bits.into_iter().skip(1));
    let mut half = acc.half;
    half.extend(upper.half);
    let (mut hits, mut zero_pre) = (acc.hits, acc.zero_pre);
    hits.sort_unstable();
    zero_pre.sort_unstable();
    let image = bitmap.iter().map(|w| w.load(Relaxed).count_ones() as u64).sum();
    Map { n: 1 << nonce_bits, image, zero_pre, lz: acc.lz, cube_all: upper.root, half, zero_bits, bit_zeros: acc.bit_zeros, hits }
}

// ------------------------------------------------------------- templates

pub(crate) struct Template {
    pub(crate) label: String,
    pub(crate) header: [u8; 80],
    /// Known block-level nonce (real templates).
    known: Option<(u32, String)>,
}

pub(crate) fn synthetic(seed: u64, i: u64) -> Template {
    let mut rng = SplitMix64::stream(seed ^ 0xa71a5, i);
    let mut prev: [u8; 32] = rng.bytes();
    prev[22..].fill(0); // internal order: the hash number's top 80 bits are zero, as for a real block
    let h = BlockHeader {
        version: (0x2000_0000 | (rng.next_u32() & 0x1fff_e000)) as i32,
        prev_blockhash: prev,
        merkle_root: rng.bytes(),
        time: 1_700_000_000 + rng.next_u32() % 100_000_000,
        bits: 0x1700_0000 | (0x8000 + rng.next_u32() % 0x7f_8000),
        nonce: 0,
    };
    Template { label: format!("synthetic-{i}"), header: h.serialize(), known: None }
}

fn real_templates() -> Vec<Template> {
    let mut out: Vec<Template> = fixtures::MAINNET
        .iter()
        .map(|k| {
            let h = BlockHeader::from_hex(k.header_hex).expect("fixture header");
            Template { label: format!("mainnet-{}", k.height), header: BlockHeader { nonce: 0, ..h }.serialize(), known: Some((k.nonce, k.hash.to_string())) }
        })
        .collect();
    let txids: Vec<[u8; 32]> = fixtures::BLOCK_100000_TXIDS.iter().map(|t| parse_display_hex(t).expect("fixture txid")).collect();
    let h = BlockHeader {
        version: 1,
        prev_blockhash: parse_display_hex(fixtures::BLOCK_100000_PREV).expect("fixture prev"),
        merkle_root: bitcoin_header::merkle_root(&txids),
        time: fixtures::BLOCK_100000_TIME,
        bits: fixtures::BLOCK_100000_BITS,
        nonce: 0,
    };
    out.push(Template { label: "mainnet-100000".into(), header: h.serialize(), known: Some((fixtures::BLOCK_100000_NONCE, fixtures::BLOCK_100000_HASH.into())) });
    out
}

pub(crate) fn prepared(header: &[u8; 80], rounds: usize) -> Prepared {
    let base = Work::new(BlockHeader::deserialize(header), Target([0xff; 32]));
    Prepared::new(&Work { midstate: HeaderMidstate::with_rounds(header, rounds), ..base })
}

// ------------------------------------------------------------- statistics

/// P(X >= k) for X ~ Poisson(lambda).
fn poisson_sf(k: u64, lambda: f64) -> f64 {
    if k == 0 { 1.0 } else { (1.0 - gamma_q(k as f64, lambda)).max(0.0) }
}

/// Two-sided Poisson p-value of observing k.
fn poisson_p(k: u64, lambda: f64) -> f64 {
    let lower = gamma_q(k as f64 + 1.0, lambda);
    (2.0 * poisson_sf(k, lambda).min(lower)).min(1.0)
}

/// P(max of `m` independent Poisson(lambda) >= k).
fn poisson_max_p(k: u64, lambda: f64, m: f64) -> f64 {
    let sf = poisson_sf(k, lambda);
    if sf >= 1.0 { 1.0 } else { -(m * (-sf).ln_1p()).exp_m1() }
}

/// Mean and standard deviation of the number of distinct values when `n`
/// values are drawn uniformly from 2^32 (exact moments, computed stably).
fn image_moments(n: u64) -> (f64, f64) {
    let m = 2f64.powi(32);
    let n = n as f64;
    let l1 = (-1.0 / m).ln_1p();
    let p1 = (n * l1).exp();
    let p2 = (n * (-2.0 / m).ln_1p()).exp();
    let delta = (-1.0 / ((m - 1.0) * (m - 1.0))).ln_1p();
    let var = m * (p1 - p2) + m * m * p1 * p1 * (n * delta).exp_m1();
    (-m * (n * l1).exp_m1(), var.max(0.0).sqrt())
}

/// In-place Walsh-Hadamard transform.
fn wht(v: &mut [i64]) {
    let mut h = 1;
    while h < v.len() {
        v.par_chunks_mut(2 * h).for_each(|c| {
            let (a, b) = c.split_at_mut(h);
            for (x, y) in a.iter_mut().zip(b) {
                (*x, *y) = (*x + *y, *x - *y);
            }
        });
        h *= 2;
    }
}

/// Projections of the nonce used for the Walsh-Hadamard scan: (shift, width).
fn projections(nonce_bits: usize) -> Vec<(usize, usize)> {
    let w = PROJ_BITS.min(nonce_bits);
    if nonce_bits > w { vec![(0, w), (nonce_bits - w, w)] } else { vec![(0, w)] }
}

/// Strategy families scored by class counts. Each strategy is a nonce class
/// with a known fraction of the nonce space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    /// Index s < 2 * nb: bit s / 2 equals s % 2; then pairs (a < b, va, vb).
    Subspace,
    /// Byte position * 256 + value.
    Byte,
    /// Hamming weight of the nonce.
    Weight,
    /// XOR neighbours of weight 1 and 2, then modular +1..+D.
    Neighbour,
}

const FAMILIES: [Family; 4] = [Family::Subspace, Family::Byte, Family::Weight, Family::Neighbour];

/// Neighbour strategies: XOR masks of weight 1 and 2, then modular steps.
fn neighbour_list(nb: usize, modular: u32) -> Vec<(bool, u32)> {
    let mut v: Vec<(bool, u32)> = (0..nb).map(|b| (true, 1u32 << b)).collect();
    for a in 0..nb {
        for b in a + 1..nb {
            v.push((true, 1 << a | 1 << b));
        }
    }
    v.extend((1..=modular).map(|d| (false, d)));
    v
}

fn label(f: Family, s: usize, nb: usize, neigh: &[(bool, u32)]) -> String {
    match f {
        Family::Subspace if s < 2 * nb => format!("nonce bit {} = {}", s / 2, s % 2),
        Family::Subspace => {
            let (a, b, va, vb) = pair_of(s - 2 * nb, nb);
            format!("nonce bits {a},{b} = {va},{vb}")
        }
        Family::Byte => format!("nonce byte {} = {:#04x}", s / 256, s % 256),
        Family::Weight => format!("nonce Hamming weight {s}"),
        Family::Neighbour => match neigh.get(s) {
            Some((true, d)) => format!("x ^ {d:#010x}"),
            Some((false, d)) => format!("x + {d}"),
            None => AGGREGATES[s - neigh.len()].to_string(),
        },
    }
}

/// Neighbour strategies that evaluate a whole group of neighbours of each hit
/// (the form of the trail-search neighbour strategy).
const AGGREGATES: [&str; 3] = ["all weight-1 XOR neighbours", "all weight-2 XOR neighbours", "all modular neighbours x + 1..x + D"];

/// Pair strategy index -> (a, b, value of a, value of b).
fn pair_of(i: usize, nb: usize) -> (usize, usize, u32, u32) {
    let (pair, vals) = (i / 4, i % 4);
    let mut k = 0;
    for a in 0..nb {
        for b in a + 1..nb {
            if k == pair {
                return (a, b, (vals >> 1) as u32, (vals & 1) as u32);
            }
            k += 1;
        }
    }
    unreachable!("pair index out of range")
}

fn n_strategies(f: Family, nb: usize, neigh: usize) -> usize {
    match f {
        Family::Subspace => 2 * nb + 4 * nb * (nb - 1) / 2,
        Family::Byte => 256 * nb.div_ceil(8),
        Family::Weight => nb + 1,
        Family::Neighbour => neigh + AGGREGATES.len(),
    }
}

/// Binomial coefficient as f64.
fn choose(n: usize, k: usize) -> f64 {
    (0..k).fold(1.0, |acc, i| acc * (n - i) as f64 / (i + 1) as f64)
}

/// (observed count, expected count, class fraction) of every strategy of a family on one template.
fn score(f: Family, hits: &[u32], nb: usize, n: u64, neigh: &[(bool, u32)]) -> Vec<(f64, f64, f64)> {
    let nh = hits.len() as f64;
    match f {
        Family::Subspace => {
            let mut c1 = vec![0u64; nb];
            let mut c11 = vec![vec![0u64; nb]; nb];
            for &x in hits {
                let bits: Vec<usize> = (0..nb).filter(|b| x >> b & 1 == 1).collect();
                for (i, &a) in bits.iter().enumerate() {
                    c1[a] += 1;
                    for &b in &bits[i + 1..] {
                        c11[a][b] += 1;
                    }
                }
            }
            let mut out: Vec<(f64, f64, f64)> = (0..2 * nb)
                .map(|s| {
                    let ones = c1[s / 2] as f64;
                    (if s % 2 == 1 { ones } else { nh - ones }, nh / 2.0, 0.5)
                })
                .collect();
            for a in 0..nb {
                for b in a + 1..nb {
                    let (ca, cb, cab) = (c1[a] as f64, c1[b] as f64, c11[a][b] as f64);
                    for c in [nh - ca - cb + cab, cb - cab, ca - cab, cab] {
                        out.push((c, nh / 4.0, 0.25));
                    }
                }
            }
            out
        }
        Family::Byte => {
            let mut c = vec![0u64; n_strategies(f, nb, 0)];
            for &x in hits {
                for byte in 0..nb.div_ceil(8) {
                    c[byte * 256 + (x >> (8 * byte) & 0xff) as usize] += 1;
                }
            }
            // A partial top byte (nb not a multiple of 8) has fewer values.
            c.iter()
                .enumerate()
                .map(|(s, &k)| {
                    let width = (nb - 8 * (s / 256)).min(8);
                    let f = if s % 256 < 1 << width { 0.5f64.powi(width as i32) } else { 0.0 };
                    (k as f64, nh * f, f)
                })
                .collect()
        }
        Family::Weight => {
            let mut c = vec![0u64; nb + 1];
            for &x in hits {
                c[x.count_ones() as usize] += 1;
            }
            c.iter()
                .enumerate()
                .map(|(w, &k)| {
                    let f = choose(nb, w) * 0.5f64.powi(nb as i32);
                    (k as f64, nh * f, f)
                })
                .collect()
        }
        Family::Neighbour => {
            let pair_p = nh * (nh - 1.0) / (n as f64 * (n as f64 - 1.0));
            let mask = (n - 1) as u32;
            let mut out: Vec<(f64, f64, f64)> = neigh
                .par_iter()
                .map(|&(is_xor, d)| {
                    let k = hits
                        .iter()
                        .filter(|&&x| {
                            let y = if is_xor { x ^ d } else { x.wrapping_add(d) & mask };
                            (!is_xor || x < y) && hits.binary_search(&y).is_ok()
                        })
                        .count() as f64;
                    // XOR masks pair the space into n/2 pairs; modular steps give n ordered pairs.
                    let pairs = if is_xor { n as f64 / 2.0 } else { n as f64 };
                    (k, pairs * pair_p, 0.0)
                })
                .collect();
            // Aggregates: the weight-1 masks come first, then weight-2, then the modular steps.
            let sum = |r: std::ops::Range<usize>| out[r].iter().fold((0.0, 0.0, 0.0), |a, s| (a.0 + s.0, a.1 + s.1, 0.0));
            let w2 = nb + nb * (nb - 1) / 2;
            let aggregates = [sum(0..nb), sum(nb..w2), sum(w2..neigh.len())];
            out.extend(aggregates);
            out
        }
    }
}

/// z of an observed class count against its expectation (binomial in the
/// class fraction f, Poisson when f = 0).
fn class_z(c: f64, e: f64, f: f64) -> f64 {
    if e <= 0.0 { 0.0 } else { (c - e) / (e * (1.0 - f)).sqrt() }
}

/// One-sided upper-tail normal p-value.
fn upper_p(z: f64) -> f64 {
    0.5 * erfc(z / std::f64::consts::SQRT_2)
}

/// Pooled scores of one family over the discovery templates.
struct Pool {
    c: Vec<f64>,
    e: Vec<f64>,
    f: Vec<f64>,
    chi: Vec<f64>,
    templates: u32,
}

impl Pool {
    fn new(m: usize) -> Self {
        Self { c: vec![0.0; m], e: vec![0.0; m], f: vec![0.0; m], chi: vec![0.0; m], templates: 0 }
    }

    fn add(&mut self, scores: &[(f64, f64, f64)]) {
        for (i, &(c, e, f)) in scores.iter().enumerate() {
            self.c[i] += c;
            self.e[i] += e;
            self.f[i] = f;
            self.chi[i] += class_z(c, e, f).powi(2);
        }
        self.templates += 1;
    }

    /// Class strategies need >= MIN_EXPECTED hits per template for the normal
    /// approximations; neighbour strategies (f = 0) use exact Poisson tails at any size.
    fn testable(&self, i: usize) -> bool {
        if self.f[i] == 0.0 { self.e[i] > 0.0 } else { self.e[i] >= MIN_EXPECTED * self.templates as f64 }
    }

    /// Strategy with the smallest pooled p-value for "more hits than expected"
    /// (usable without template knowledge) and for "any deviation" (chi-square
    /// over templates, or two-sided Poisson for neighbours), with family-wise
    /// (Bonferroni) p-values.
    fn best(&self) -> (usize, f64, usize, f64) {
        let ok: Vec<usize> = (0..self.c.len()).filter(|&i| self.testable(i)).collect();
        let m = ok.len().max(1) as f64;
        let argmin = |p: &dyn Fn(usize) -> f64| ok.iter().copied().min_by(|&a, &b| p(a).total_cmp(&p(b))).unwrap_or(0);
        let p_u = |i: usize| usable_p(self.c[i], self.e[i], self.f[i]);
        let p_s = |i: usize| structure_p(self.c[i], self.e[i], self.f[i], self.chi[i], self.templates);
        let (u, s) = (argmin(&p_u), argmin(&p_s));
        (u, (m * p_u(u)).min(1.0), s, (m * p_s(s)).min(1.0))
    }

    fn z(&self, i: usize) -> f64 {
        class_z(self.c[i], self.e[i], self.f[i])
    }
}

/// Smallest expected hits per template for a class strategy to be tested.
const MIN_EXPECTED: f64 = 5.0;

/// One-sided p of a pooled count exceeding its expectation.
fn usable_p(c: f64, e: f64, f: f64) -> f64 {
    if f == 0.0 { poisson_sf(c as u64, e) } else { upper_p(class_z(c, e, f)) }
}

/// p of any deviation: chi-square of per-template z over `t` templates, or two-sided Poisson.
fn structure_p(c: f64, e: f64, f: f64, chi: f64, t: u32) -> f64 {
    if f == 0.0 { poisson_p(c as u64, e) } else { chi2_sf(chi, t as f64) }
}

/// Amplification A = observed / expected with the 95% Poisson score interval
/// (c - λ)² / λ = z², and the work per hit relative to exhaustive search (1 / A).
fn amplification(c: f64, e: f64) -> Value {
    if e <= 0.0 {
        return json!(null);
    }
    let r = (c + Z95 * Z95 / 4.0).sqrt();
    let (lo, hi) = ((r - Z95 / 2.0).powi(2) / e, (r + Z95 / 2.0).powi(2) / e);
    let inv = |x: f64| (x > 0.0).then(|| 1.0 / x);
    json!({ "A": c / e, "ci95": [lo, hi], "work_factor": inv(c / e), "work_factor_ci95": [1.0 / hi, inv(lo)], "observed": c, "expected": e })
}

/// Walsh-Hadamard scan of linear half-space strategies on one template:
/// pooled sum of W(u) and of W(u)^2 / N per mask, per projection.
struct WalshPool {
    proj: Vec<(usize, usize)>,
    sum_w: Vec<Vec<f64>>,
    chi: Vec<Vec<f64>>,
    hits: f64,
    templates: u32,
}

impl WalshPool {
    fn new(nb: usize) -> Self {
        let proj = projections(nb);
        let len = |w: usize| 1usize << w;
        Self { sum_w: proj.iter().map(|p| vec![0.0; len(p.1)]).collect(), chi: proj.iter().map(|p| vec![0.0; len(p.1)]).collect(), proj, hits: 0.0, templates: 0 }
    }

    fn add(&mut self, hits: &[u32]) {
        let nh = hits.len() as f64;
        for (k, &(shift, width)) in self.proj.iter().enumerate() {
            let mut v = vec![0i64; 1 << width];
            for &x in hits {
                v[(x >> shift) as usize & ((1 << width) - 1)] += 1;
            }
            wht(&mut v);
            self.sum_w[k].par_iter_mut().zip(self.chi[k].par_iter_mut()).zip(v.par_iter()).for_each(|((s, c), &w)| {
                *s += w as f64;
                *c += (w * w) as f64 / nh.max(1.0);
            });
        }
        self.hits += nh;
        self.templates += 1;
    }

    /// Best (projection, mask) by |pooled W| and by chi-square, with family-wise p-values.
    fn best(&self) -> (Mask, f64, Mask, f64) {
        let masks: f64 = self.proj.iter().map(|p| ((1u64 << p.1) - 1) as f64).sum();
        let arg = |vals: &Vec<Vec<f64>>, key: &dyn Fn(f64) -> f64| -> Mask {
            let mut best = Mask { proj: 0, mask: 1 };
            let mut bv = f64::NEG_INFINITY;
            for (k, v) in vals.iter().enumerate() {
                for (u, &x) in v.iter().enumerate().skip(1) {
                    if key(x) > bv {
                        (bv, best) = (key(x), Mask { proj: k, mask: u });
                    }
                }
            }
            best
        };
        let usable = arg(&self.sum_w, &|x: f64| x.abs());
        let structure = arg(&self.chi, &|x| x);
        let z = self.sum_w[usable.proj][usable.mask] / self.hits.max(1.0).sqrt();
        let p_usable = (masks * two_sided_p(z)).min(1.0);
        let p_structure = (masks * chi2_sf(self.chi[structure.proj][structure.mask], self.templates as f64)).min(1.0);
        (usable, p_usable, structure, p_structure)
    }
}

#[derive(Clone, Copy, Debug)]
struct Mask {
    proj: usize,
    mask: usize,
}

impl Mask {
    /// Nonce-level mask of this projection mask.
    fn nonce_mask(&self, proj: &[(usize, usize)]) -> u32 {
        (self.mask as u32) << proj[self.proj].0
    }

    /// W(u) = #hits with u.x = 0 minus #hits with u.x = 1.
    fn walsh(&self, proj: &[(usize, usize)], hits: &[u32]) -> f64 {
        let m = self.nonce_mask(proj);
        hits.iter().map(|x| if (x & m).count_ones().is_multiple_of(2) { 1.0 } else { -1.0 }).sum()
    }
}

/// Every pairwise XOR or canonical modular difference among `hits`:
/// largest multiplicity, the smallest difference reaching it, and the
/// null probability of a maximum that large over all differences.
fn all_differences(hits: &[u32], n: u64, is_xor: bool) -> (u64, u32, f64, f64) {
    let mut d: Vec<u32> = hits
        .par_iter()
        .enumerate()
        .flat_map_iter(|(i, &x)| {
            hits[i + 1..].iter().map(move |&y| {
                if is_xor {
                    x ^ y
                } else {
                    let diff = (y as u64).wrapping_sub(x as u64) & (n - 1);
                    diff.min(n - diff) as u32
                }
            })
        })
        .collect();
    d.par_sort_unstable();
    let (mut best, mut arg, mut i) = (0u64, 0u32, 0);
    while i < d.len() {
        let j = i + d[i..].partition_point(|&v| v == d[i]);
        if (j - i) as u64 > best {
            (best, arg) = ((j - i) as u64, d[i]);
        }
        i = j;
    }
    let lambda = expected_pairs(hits.len(), n, is_xor);
    let classes = if is_xor { (n - 1) as f64 } else { (n / 2) as f64 };
    (best, arg, lambda, poisson_max_p(best, lambda, classes))
}

/// Expected number of hit pairs with one given XOR (or canonical modular) difference.
fn expected_pairs(nh: usize, n: u64, is_xor: bool) -> f64 {
    let nh = nh as f64;
    let pairs = if is_xor { n as f64 / 2.0 } else { n as f64 };
    pairs * nh * (nh - 1.0) / (n as f64 * (n as f64 - 1.0))
}

fn count_pairs(hits: &[u32], n: u64, is_xor: bool, d: u32) -> u64 {
    let mask = (n - 1) as u32;
    hits.iter()
        .filter(|&&x| {
            if is_xor {
                let y = x ^ d;
                x < y && hits.binary_search(&y).is_ok()
            } else {
                // Canonical class d covers both x + d and x - d; count each unordered pair once.
                hits.binary_search(&(x.wrapping_add(d) & mask)).is_ok() && (2 * d as u64 != n || x < x.wrapping_add(d) & mask)
            }
        })
        .count() as u64
}

// ------------------------------------------------------------- execution

/// Template-level statistics (no strategies).
/// Template-level record and the image-size p-value.
fn template_stats(t: &Template, m: &Map, k_store: u32, rounds: usize, nb: usize) -> (Value, f64) {
    let (e, sd) = image_moments(m.n);
    let z = (m.image as f64 - e) / sd;
    let half_zero: u64 = m.half.iter().flatten().map(|w| w.count_zeros() as u64).sum();
    let all_zero: u64 = m.cube_all.iter().map(|w| w.count_zeros() as u64).sum();
    let mut zero_words: Vec<String> = (0..8).filter(|&i| m.cube_all[i] == 0).map(|i| format!("full cube H{i}")).collect();
    for (b, w) in m.half.iter().enumerate() {
        zero_words.extend((0..8).filter(|&i| w[i] == 0).map(|i| format!("bit {b} = 0 H{i}")));
    }
    // A missing known nonce is an implementation error: `verify` fails on it.
    let known = t.known.as_ref().filter(|_| rounds == FULL_ROUNDS && nb == 32).map(|(nonce, hash)| {
        let found = m.hits.iter().find(|h| h.0 == *nonce).map(|h| h.1);
        json!({ "nonce": nonce, "block_hash": hash, "leading_zeros_found": found, "in_zero_preimages": m.zero_pre.contains(nonce) })
    });
    let v = json!({
        "template": t.label,
        "nonces": m.n,
        "image": { "observed": m.image, "expected": e, "sd": sd, "z": z },
        "top_word_zero_preimages": { "count": m.zero_pre.len(), "expected": m.n as f64 / 2f64.powi(32), "nonces": m.zero_pre },
        "known_block": known,
        "hits_at_k_store": m.hits.len(),
        "expected_hits_at_k_store": m.n as f64 * 0.5f64.powi(k_store as i32),
        "hits_digest": digest(&json!(m.hits)),
        "hit_sample": m.hits.iter().take(4).map(|h| json!([h.0, h.1])).collect::<Vec<_>>(),
        "cube": { "full_cube_zero_bits": all_zero, "half_cubes_zero_bits": half_zero, "half_cube_bits": m.half.len() * 256, "zero_words": zero_words, "full_cube_xor": crate::hex_words(&m.cube_all) },
        "lz_histogram": m.lz.to_vec(),
    });
    (v, two_sided_p(z))
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let nb = p_u64(params, "nonce_bits")? as usize;
    ensure!((CHUNK_BITS..=32).contains(&nb), "nonce_bits must be 16..=32");
    let k_store = p_u64(params, "k_store")? as u32;
    let k_pair = p_u64(params, "k_pair")? as u32;
    ensure!(k_store <= k_pair && k_pair <= 64, "need k_store <= k_pair <= 64");
    let n_syn = p_u64(params, "synthetic_templates")?;
    let n_red = p_u64(params, "reduced_templates")?;
    ensure!(n_syn >= 2 && n_red >= 2, "need at least 2 templates per round count (discovery and held-out)");
    let with_real = params["real_templates"].as_bool().unwrap_or(false);
    let modular = p_u64(params, "modular_neighbours")? as u32;
    let alpha = p_f64(params, "alpha")?;
    let neigh = neighbour_list(nb, modular);

    let mut configs = Vec::new();
    let mut all_p: Vec<(usize, String, f64)> = Vec::new();
    for &r in &rounds {
        ensure!(r >= 3, "rounds must be >= 3 (rounds 0..2 are precomputed)");
        let count = if r == FULL_ROUNDS { n_syn } else { n_red };
        let syn: Vec<Template> = (0..count).map(|i| synthetic(seed, i)).collect();
        let n_disc = count.div_ceil(2) as usize;
        let mut held: Vec<Template> = Vec::new();
        let mut disc = syn;
        held.extend(disc.split_off(n_disc));
        if r == FULL_ROUNDS && with_real {
            held.extend(real_templates());
        }

        let mut templates = Vec::new();
        let mut pools: Vec<Pool> = FAMILIES.iter().map(|&f| Pool::new(n_strategies(f, nb, neigh.len()))).collect();
        let mut walsh = WalshPool::new(nb);
        let mut pooled_lz = [0u64; 65];
        let mut pooled_zero = (0u64, 0.0f64);
        let mut levels = vec![[0u64; 8]; nb + 1];
        let mut bit_zeros = vec![0u64; 256];
        let mut cube = (0u64, 0u64, 0usize);
        let mut ad_disc: Vec<Value> = Vec::new();
        let mut ad_best: [(u64, u32, f64); 2] = [(0, 0, 1.0); 2];
        // Held-out templates: (hits at k_store, hits at k_pair, nonces).
        let mut held_maps: Vec<(Vec<u32>, Vec<u32>, u64)> = Vec::new();
        let n = 1u64 << nb;

        for (role, list) in [("discovery", &disc), ("held-out", &held)] {
            for t in list {
                let m = enumerate(&prepared(&t.header, r), nb, k_store);
                let (mut v, p_image) = template_stats(t, &m, k_store, r, nb);
                v["role"] = json!(role);
                all_p.push((r, format!("{} image size", t.label), p_image));
                for (a, b) in pooled_lz.iter_mut().zip(m.lz) {
                    *a += b;
                }
                if t.known.is_none() {
                    pooled_zero.0 += m.zero_pre.len() as u64;
                    pooled_zero.1 += m.n as f64 / 2f64.powi(32);
                }
                for (a, b) in levels.iter_mut().zip(&m.zero_bits) {
                    a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
                }
                bit_zeros.iter_mut().zip(&m.bit_zeros).for_each(|(a, b)| *a += b);
                let cube_words = m.cube_all.iter().chain(m.half.iter().flatten());
                cube.0 += cube_words.clone().map(|w| w.count_zeros() as u64).sum::<u64>();
                cube.1 += 32 * cube_words.clone().count() as u64;
                cube.2 += cube_words.filter(|&&w| w == 0).count();
                let hits: Vec<u32> = m.hits.iter().map(|h| h.0).collect();
                let pair_hits: Vec<u32> = m.hits.iter().filter(|h| h.1 as u32 >= k_pair).map(|h| h.0).collect();
                if role == "discovery" {
                    for (pool, &f) in pools.iter_mut().zip(&FAMILIES) {
                        pool.add(&score(f, &hits, nb, n, &neigh));
                    }
                    walsh.add(&hits);
                    let mut per = Vec::new();
                    for (k, is_xor) in [true, false].into_iter().enumerate() {
                        let (mult, d, lambda, p) = all_differences(&pair_hits, n, is_xor);
                        per.push(json!({ "kind": if is_xor { "xor" } else { "modular" }, "max_multiplicity": mult, "difference": d, "expected_per_difference": lambda, "p_max": p }));
                        if p < ad_best[k].2 || (p == ad_best[k].2 && mult > ad_best[k].0) {
                            ad_best[k] = (mult, d, p);
                        }
                    }
                    ad_disc.push(json!({ "template": t.label, "pair_hits": pair_hits.len(), "differences": per }));
                } else {
                    held_maps.push((hits, pair_hits, m.n));
                }
                templates.push(v);
            }
        }

        // Template-independent pooled statistics.
        let (ez, oz) = (pooled_zero.1, pooled_zero.0);
        all_p.push((r, "zero preimages (synthetic, pooled)".into(), poisson_p(oz, ez)));
        let lz_tail = (0..64).take_while(|&k| (n * templates.len() as u64) as f64 * 0.5f64.powi(k + 1) >= 5.0).count();
        let (mut chi_lz, total) = (0.0, (n * templates.len() as u64) as f64);
        for k in 0..=lz_tail {
            let (obs, exp) = if k < lz_tail { (pooled_lz[k] as f64, total * 0.5f64.powi(k as i32 + 1)) } else { (pooled_lz[k..].iter().sum::<u64>() as f64, total * 0.5f64.powi(k as i32)) };
            chi_lz += (obs - exp).powi(2) / exp;
        }
        let p_lz = chi2_sf(chi_lz, lz_tail as f64);
        all_p.push((r, "leading-zero histogram (pooled)".into(), p_lz));
        let cube_z = (cube.0 as f64 - cube.1 as f64 / 2.0) / (cube.1 as f64 / 4.0).sqrt();
        all_p.push((r, "cube-sum zero bits (pooled)".into(), two_sided_p(cube_z)));
        let words = cube.1 as f64 / 32.0;
        all_p.push((r, "cube-sum zero words (pooled)".into(), poisson_sf(cube.2 as u64, words * 0.5f64.powi(32))));
        let level_stats: Vec<Value> = (LEVEL_MIN..=nb)
            .map(|j| {
                let nodes = (n >> j) * templates.len() as u64;
                let zeros: u64 = levels[j].iter().sum();
                let bits = (nodes * 256) as f64;
                let z = (zeros as f64 - bits / 2.0) / (bits / 4.0).sqrt();
                let per_word: Vec<f64> = levels[j].iter().map(|&zw| zw as f64 / (nodes * 32) as f64).collect();
                all_p.push((r, format!("sub-cube zero rate, dimension {j}"), two_sided_p(z)));
                json!({ "dimension": j, "nodes": nodes, "zero_rate": zeros as f64 / bits, "zero_rate_per_word": per_word, "z": z })
            })
            .collect();
        // Per output bit at dimension LEVEL_MIN: which bits carry a degree deficiency in the low nonce byte.
        let nodes8 = ((n >> LEVEL_MIN) * templates.len() as u64) as f64;
        let bit_z: Vec<f64> = bit_zeros.iter().map(|&z| (z as f64 - nodes8 / 2.0) / (nodes8 / 4.0).sqrt()).collect();
        let max_bit = (0..256).max_by(|&a, &b| bit_z[a].abs().total_cmp(&bit_z[b].abs())).unwrap_or(0);
        all_p.push((r, format!("sub-cube zero rate per bit, dimension {LEVEL_MIN} (max of 256)"), (256.0 * two_sided_p(bit_z[max_bit])).min(1.0)));
        let mut ranked: Vec<usize> = (0..256).collect();
        ranked.sort_by(|&a, &b| bit_z[b].abs().total_cmp(&bit_z[a].abs()));
        let bit_stats = json!({
            "dimension": LEVEL_MIN,
            "nodes": nodes8,
            "h7_zero_rate_by_bit": (224..256).map(|i| bit_zeros[i] as f64 / nodes8).collect::<Vec<_>>(),
            "h7_z_by_bit": bit_z[224..].to_vec(),
            "top": ranked.iter().take(8).map(|&i| json!({ "word": format!("H{}", i / 32), "bit": i % 32, "zero_rate": bit_zeros[i] as f64 / nodes8, "z": bit_z[i] })).collect::<Vec<_>>(),
        });

        // Strategies: discovery winners re-measured on held-out templates.
        let mut strategies = serde_json::Map::new();
        for (pool, &f) in pools.iter().zip(&FAMILIES) {
            let (u, pu, s, psx) = pool.best();
            // Held-out: the usable winner's pooled count, the structure winner's chi-square.
            let (mut hc, mut he, mut hchi) = (0.0, 0.0, 0.0);
            let (mut sc, mut se) = (0.0, 0.0);
            for (hits, _, n_t) in &held_maps {
                let all = score(f, hits, nb, *n_t, &neigh);
                (hc, he) = (hc + all[u].0, he + all[u].1);
                let (c, e, fr) = all[s];
                (sc, se) = (sc + c, se + e);
                hchi += class_z(c, e, fr).powi(2);
            }
            let p_hu = usable_p(hc, he, pool.f[u]);
            let p_hs = structure_p(sc, se, pool.f[s], hchi, held_maps.len() as u32);
            all_p.push((r, format!("{f:?} usable"), pu.max(p_hu)));
            all_p.push((r, format!("{f:?} structure"), psx.max(p_hs)));
            strategies.insert(format!("{f:?}").to_lowercase(), json!({
                "strategies": pool.c.len(),
                "discovery_templates": pool.templates,
                "best_usable": { "strategy": label(f, u, nb, &neigh), "discovery": amplification(pool.c[u], pool.e[u]), "discovery_z": pool.z(u), "p_family": pu, "held_out": amplification(hc, he), "p_held_out": p_hu },
                "best_structure": { "strategy": label(f, s, nb, &neigh), "discovery_chi2": pool.chi[s], "df": pool.templates, "p_family": psx, "held_out_chi2": hchi, "held_out_df": held_maps.len(), "p_held_out": p_hs, "held_out": amplification(sc, se) },
            }));
        }
        let (wu, wpu, ws, wps) = walsh.best();
        // The usable winner is the half-space parity(nonce & u) = s with s fixed by the discovery sign.
        let sign = if walsh.sum_w[wu.proj][wu.mask] >= 0.0 { 1.0 } else { -1.0 };
        let (mut w_held, mut w_hits, mut w_chi) = (0.0, 0.0, 0.0);
        for (hits, _, _) in &held_maps {
            w_held += sign * wu.walsh(&walsh.proj, hits);
            w_hits += hits.len() as f64;
            let w = ws.walsh(&walsh.proj, hits);
            w_chi += w * w / (hits.len() as f64).max(1.0);
        }
        let p_wu = upper_p(w_held / w_hits.max(1.0).sqrt());
        let p_ws = chi2_sf(w_chi, held_maps.len() as f64);
        all_p.push((r, "linear half-space usable".into(), wpu.max(p_wu)));
        all_p.push((r, "linear half-space structure".into(), wps.max(p_ws)));
        // The half-space holds (N + W) / 2 of N hits against N / 2 expected: A = 1 + W / N.
        let half_amp = |w: f64, nh: f64| json!({ "A": 1.0 + w / nh.max(1.0), "work_factor": 1.0 / (1.0 + w / nh.max(1.0)), "z": w / nh.max(1.0).sqrt() });
        strategies.insert("linear".into(), json!({
            "strategies": walsh.proj.iter().map(|p| (1u64 << p.1) - 1).sum::<u64>(),
            "projections": walsh.proj.iter().map(|p| json!({ "shift": p.0, "width": p.1 })).collect::<Vec<_>>(),
            "best_usable": { "strategy": format!("parity(nonce & {:#010x}) = {}", wu.nonce_mask(&walsh.proj), if sign > 0.0 { 0 } else { 1 }),
                              "discovery": half_amp(sign * walsh.sum_w[wu.proj][wu.mask], walsh.hits), "p_family": wpu,
                              "held_out": half_amp(w_held, w_hits), "p_held_out": p_wu },
            "best_structure": { "strategy": format!("mask {:#010x}", ws.nonce_mask(&walsh.proj)), "discovery_chi2": walsh.chi[ws.proj][ws.mask], "df": walsh.templates, "p_family": wps, "held_out_chi2": w_chi, "held_out_df": held_maps.len(), "p_held_out": p_ws },
        }));
        let mut ad_held = Vec::new();
        for (k, is_xor) in [true, false].into_iter().enumerate() {
            let (_, d, p_disc) = ad_best[k];
            let (mut c, mut e) = (0u64, 0.0);
            for (_, ph, n_t) in &held_maps {
                c += count_pairs(ph, *n_t, is_xor, d);
                e += expected_pairs(ph.len(), *n_t, is_xor) * if !is_xor && 2 * d as u64 == *n_t { 0.5 } else { 1.0 };
            }
            let p_held = poisson_sf(c, e);
            all_p.push((r, format!("all {} differences", if is_xor { "XOR" } else { "modular" }), p_disc.max(p_held)));
            ad_held.push(json!({ "kind": if is_xor { "xor" } else { "modular" }, "difference": d, "p_discovery_best": p_disc, "held_out_pairs": c, "held_out_expected": e, "p_held_out": p_held, "held_out": amplification(c as f64, e) }));
        }
        configs.push(json!({
            "rounds": r,
            "templates": templates,
            "pooled": {
                "zero_preimages_synthetic": { "count": oz, "expected": ez },
                "lz_chi2": { "stat": chi_lz, "df": lz_tail, "p": p_lz },
                "cube_zero_bits": { "zeros": cube.0, "bits": cube.1, "z": cube_z, "zero_words": cube.2 },
                "sub_cube_levels": level_stats,
                "sub_cube_bits": bit_stats,
            },
            "strategies": strategies,
            "all_differences": { "k_pair": k_pair, "discovery": ad_disc, "held_out": ad_held },
        }));
    }

    // Bonferroni over every p-value of every round count.
    let threshold = alpha / all_p.len().max(1) as f64;
    let mut flags = Vec::new();
    let mut summary = Vec::new();
    for c in configs.iter_mut() {
        let r = c["rounds"].as_u64().unwrap_or(0) as usize;
        let sig: Vec<Value> = all_p.iter().filter(|(rr, _, p)| *rr == r && *p < threshold).map(|(_, name, p)| json!({ "test": name, "p": p })).collect();
        flags.push((r, !sig.is_empty()));
        c["significant"] = json!(sig);
        c["tests"] = json!(all_p.iter().filter(|(rr, _, _)| *rr == r).count());
        c["deviation_detected"] = json!(!sig.is_empty());
    }
    summary.push(format!("{} p-values, Bonferroni threshold {threshold:.3e}.", all_p.len()));
    for c in &configs {
        let r = c["rounds"].as_u64().unwrap_or(0);
        let s = &c["strategies"];
        let held: Vec<String> = ["subspace", "byte", "weight", "neighbour", "linear"]
            .iter()
            .map(|f| {
                let h = &s[*f]["best_usable"]["held_out"];
                let ci = h["ci95"].as_array().map_or(String::new(), |v| format!(" [{:.3}, {:.3}]", v[0].as_f64().unwrap_or(f64::NAN), v[1].as_f64().unwrap_or(f64::NAN)));
                format!("{f} {:.4}{ci}", h["A"].as_f64().unwrap_or(f64::NAN))
            })
            .collect();
        summary.push(format!(
            "{r} rounds: {} significant tests; image z range [{:.2}, {:.2}]; held-out amplification of each family's discovery winner: {}.",
            c["significant"].as_array().map_or(0, Vec::len),
            c["templates"].as_array().into_iter().flatten().filter_map(|t| t["image"]["z"].as_f64()).fold(f64::INFINITY, f64::min),
            c["templates"].as_array().into_iter().flatten().filter_map(|t| t["image"]["z"].as_f64()).fold(f64::NEG_INFINITY, f64::max),
            held.join(", "),
        ));
    }
    let counterexamples: Vec<Value> = configs
        .iter()
        .flat_map(|c| c["significant"].as_array().cloned().unwrap_or_default().into_iter().map(move |s| json!({ "rounds": c["rounds"], "test": s["test"], "p": s["p"] })))
        .collect();
    let obs = json!({ "nonce_bits": nb, "k_store": k_store, "k_pair": k_pair, "bonferroni_threshold": threshold, "configurations": configs });
    let mut o = Outcome::new(obs.clone(), obs, flags, summary);
    o.counterexamples = counterexamples;
    Ok(o)
}

/// Independent check of the enumerator and its accumulators: for one
/// synthetic template per round count, every nonce in 0..2^16 is hashed with
/// the independent SHA-256 over the serialized header and every statistic is
/// recomputed by its definition. Real templates: the known block hash.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let ind = verification::independent::Sha256::default();
    let k_store = p_u64(params, "k_store")? as u32;
    let mut problems = Vec::new();
    let bits = 16usize;
    for r in p_rounds(params)? {
        let t = synthetic(seed, 0);
        let fast = enumerate(&prepared(&t.header, r), bits, k_store.min(8));
        let outs: Vec<Words> = (0..1u32 << bits)
            .into_par_iter()
            .map(|nonce| {
                let mut h = t.header;
                h[76..80].copy_from_slice(&nonce.to_le_bytes());
                let d = ind.sha256d(&h, r);
                std::array::from_fn(|i| u32::from_be_bytes(d[4 * i..4 * i + 4].try_into().expect("4 bytes")))
            })
            .collect();
        let mut tops: Vec<u32> = outs.iter().map(|h| h[7].swap_bytes()).collect();
        let zero_pre: Vec<u32> = (0..outs.len() as u32).filter(|&i| tops[i as usize] == 0).collect();
        tops.sort_unstable();
        tops.dedup();
        let mut lz = [0u64; 65];
        let mut hits = Vec::new();
        for (i, h) in outs.iter().enumerate() {
            let z = leading_zeros(h);
            lz[z as usize] += 1;
            if z >= k_store.min(8) {
                hits.push((i as u32, z as u8));
            }
        }
        let cube_all = outs.iter().fold([0u32; 8], |a, h| xor(a, *h));
        let half: Vec<Words> = (0..bits).map(|b| outs.iter().enumerate().filter(|(i, _)| i >> b & 1 == 0).fold([0u32; 8], |a, (_, h)| xor(a, *h))).collect();
        let level_ok = (LEVEL_MIN..=bits).all(|j| {
            let zeros: u64 = outs.chunks(1 << j).map(|c| c.iter().fold([0u32; 8], |a, h| xor(a, *h)).iter().map(|w| w.count_zeros() as u64).sum::<u64>()).sum();
            zeros == fast.zero_bits[j].iter().sum::<u64>()
        });
        let mut bit_zeros = vec![0u64; 256];
        for c in outs.chunks(1 << LEVEL_MIN) {
            let x = c.iter().fold([0u32; 8], |a, h| xor(a, *h));
            for (i, z) in bit_zeros.iter_mut().enumerate() {
                *z += (x[i / 32] >> (i % 32) & 1 == 0) as u64;
            }
        }
        let level_ok = level_ok && bit_zeros == fast.bit_zeros;
        let checks = [
            ("image", fast.image == tops.len() as u64),
            ("zero preimages", fast.zero_pre == zero_pre),
            ("leading-zero histogram", fast.lz == lz),
            ("hits", fast.hits == hits),
            ("full cube", fast.cube_all == cube_all),
            ("half cubes", fast.half == half),
            ("sub-cube zero bits", level_ok),
        ];
        problems.extend(checks.iter().filter(|c| !c.1).map(|c| format!("r{r}: {} differs", c.0)));
    }
    // Known blocks: independent hash of the real header equals the block hash.
    let nb = p_u64(params, "nonce_bits")?;
    if params["real_templates"].as_bool().unwrap_or(false) && nb == 32 {
        for t in real_templates() {
            let (nonce, want) = t.known.clone().expect("real template");
            let mut h = t.header;
            h[76..80].copy_from_slice(&nonce.to_le_bytes());
            let mut d = ind.sha256d(&h, FULL_ROUNDS);
            d.reverse();
            if bitcoin_header::hex_encode(&d) != want {
                problems.push(format!("{}: independent hash differs from the block hash", t.label));
            }
        }
        let found = outcome.observations["configurations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["rounds"] == FULL_ROUNDS)
            .flat_map(|c| c["templates"].as_array().cloned().unwrap_or_default())
            .filter(|t| t["known_block"].is_object())
            .all(|t| t["known_block"]["leading_zeros_found"].as_u64().is_some_and(|z| z >= 32));
        if !found {
            problems.push("a known block nonce was not found by the enumeration".into());
        }
    }
    // Sampled stored hits, recomputed independently.
    for c in outcome.observations["configurations"].as_array().into_iter().flatten() {
        let r = c["rounds"].as_u64().unwrap_or(64) as usize;
        for (i, t) in c["templates"].as_array().into_iter().flatten().enumerate().take(2) {
            let header = if t["template"].as_str().is_some_and(|l| l.starts_with("synthetic-")) {
                let idx: u64 = t["template"].as_str().and_then(|l| l.strip_prefix("synthetic-")).and_then(|s| s.parse().ok()).unwrap_or(i as u64);
                synthetic(seed, idx).header
            } else {
                continue;
            };
            for h in t["hit_sample"].as_array().into_iter().flatten() {
                let (nonce, z) = (h[0].as_u64().unwrap_or(0) as u32, h[1].as_u64().unwrap_or(0) as u32);
                let mut hd = header;
                hd[76..80].copy_from_slice(&nonce.to_le_bytes());
                let d = ind.sha256d(&hd, r);
                let w: Words = std::array::from_fn(|i| u32::from_be_bytes(d[4 * i..4 * i + 4].try_into().expect("4 bytes")));
                if leading_zeros(&w) != z || z < k_store {
                    problems.push(format!("r{r} {} nonce {nonce}: stored hit not reproduced", t["template"]));
                }
            }
        }
    }
    problems.truncate(10);
    Ok(Verification {
        method: "independent SHA-256 over serialized headers: every statistic of the first synthetic template recomputed from its definition over nonces 0..2^16 at every round count; known mainnet block hashes; stored hit samples rehashed".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "enumerator, XOR tree, bitmap and hit list identical to the definitions; known blocks and hit samples reproduced".into() } else { problems.join("; ") },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_moments_match_known_limits() {
        // n = 2^32 balls in 2^32 bins: mean (1 - 1/e) 2^32, variance 2^32 (1/e - 2/e^2).
        let (m, sd) = image_moments(1 << 32);
        let n = 2f64.powi(32);
        assert!((m / n - (1.0 - (-1f64).exp())).abs() < 1e-9);
        assert!((sd - (n * ((-1f64).exp() - 2.0 * (-2f64).exp())).sqrt()).abs() / sd < 1e-6);
        // Few balls: almost no collisions, variance ~ number of expected collisions.
        let (m, sd) = image_moments(1 << 16);
        assert!((65536.0 - m - 0.5).abs() < 0.01 && (sd - 0.5f64.sqrt()).abs() < 0.01);
    }

    #[test]
    fn walsh_transform_and_tree_match_definitions() {
        let mut v = vec![3i64, 1, 0, 2];
        wht(&mut v);
        assert_eq!(v, [6, 0, 2, 4]);
        let mut t = Tree::new(3, 0);
        let vals: Vec<Words> = (0..8u32).map(|i| [i * 7 + 1; 8]).collect();
        for (i, v) in vals.iter().enumerate() {
            t.push(i as u64, *v);
        }
        assert_eq!(t.root, vals.iter().fold([0; 8], |a, v| xor(a, *v)));
        for b in 0..3 {
            let want = vals.iter().enumerate().filter(|(i, _)| i >> b & 1 == 0).fold([0; 8], |a, (_, v)| xor(a, *v));
            assert_eq!(t.half[b], want, "bit {b}");
        }
    }

    #[test]
    fn four_round_positive_control_is_a_permutation_with_affine_hits() {
        // At 4 rounds H7 = K + bswap(nonce): the top word is a bijection of the nonce.
        let t = synthetic(1, 0);
        let m = enumerate(&prepared(&t.header, 4), 16, 4);
        assert_eq!(m.image, 1 << 16);
        // Nonces 0..2^16 only touch the top 16 bits of bswap(nonce), so the low 16 bits of
        // H7 (the top 16 bits of the hash number) are constant: one leading-zero class.
        assert_eq!(m.lz.iter().filter(|&&c| c > 0).count(), 1);
    }

    #[test]
    fn pair_and_difference_counts_match_brute_force() {
        let hits: Vec<u32> = vec![1, 2, 3, 5, 8, 13, 21, 34, 1000, 1001];
        let n = 1u64 << 16;
        for d in [1u32, 3, 8, 13] {
            let brute = hits.iter().filter(|&&x| hits.contains(&(x ^ d)) && x < (x ^ d)).count() as u64;
            assert_eq!(count_pairs(&hits, n, true, d), brute);
            let brute_mod = hits.iter().filter(|&&x| hits.contains(&((x + d) & 0xffff))).count() as u64;
            assert_eq!(count_pairs(&hits, n, false, d), brute_mod);
        }
        for is_xor in [true, false] {
            let mut counts = std::collections::BTreeMap::new();
            for (i, &x) in hits.iter().enumerate() {
                for &y in &hits[i + 1..] {
                    let d = if is_xor { x ^ y } else { (y - x).min(65536 - (y - x)) };
                    *counts.entry(d).or_insert(0u64) += 1;
                }
            }
            let max = *counts.values().max().unwrap();
            let arg = *counts.iter().find(|e| *e.1 == max).unwrap().0;
            let (mult, d, _, _) = all_differences(&hits, n, is_xor);
            assert_eq!((mult, d), (max, arg), "xor {is_xor}");
        }
    }
}
