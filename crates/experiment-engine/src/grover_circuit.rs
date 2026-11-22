//! Grover search on the real Bitcoin header function, gate by gate.
//!
//! The oracle is built as a reversible circuit (X, CNOT, Toffoli) of the
//! header SHA256d: midstate, the template's constant words and every value
//! that depends only on them are classical (no qubits, no gates); the m low
//! bits of the nonce word W3 are the search register. Additions are Cuccaro
//! ripple-carry adders, Sigma/sigma are CNOT networks, Ch and Maj one
//! Toffoli per bit, and every temporary is uncomputed. The phase oracle
//! marks inputs whose hash number has d leading zero bits.
//!
//! The circuit maps basis states to basis states and returns the workspace to
//! zero, so between oracle calls the state is 2^m real amplitudes over the
//! search register, whatever the number of qubits. Ideal simulation is exact.
//! This allows Grover on the full 64-round SHA256d with a small search
//! register:
//! * the circuit is checked on every one of the 2^m inputs (hash register
//!   equals the reference SHA-256, workspace returns to zero);
//! * ideal Grover iterations are compared with sin^2((2k + 1) theta);
//! * noisy runs inject Pauli X or Z errors after gates with probability p
//!   (Monte Carlo trajectories) to find the error rate at which Grover stops
//!   beating a random guess. An input left with garbage in its workspace
//!   after an oracle call can no longer interfere with the others: its
//!   probability is set aside as decohered and counted as a random guess.
//!
//! Resource counts are exact for this construction and comparable with the
//! analytical `quantum-model` record. No quantum hardware is involved.

use crate::{Definition, Outcome, Verification, p_rounds, p_u64};
use anyhow::{Context, Result};
use bitcoin_header::HeaderMidstate;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::{IV, K, big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use statistical_engine::{SplitMix64, mean_ci95};

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-QUANT-02",
        primitive: crate::primitive::HEADER,
        name: "Gate-level Grover on the Bitcoin header SHA256d: verified circuit, exact resources, noise threshold",
        version: 1,
        hypothesis: "A Grover oracle for the Bitcoin header target can be built and run correctly, and keeps its quadratic advantage at physical error rates of current quantum hardware (about 1e-3 per gate).",
        null_hypothesis: "The circuit is correct, but its size makes Grover no better than a random guess unless the error per gate is many orders of magnitude below current hardware.",
        assumptions: &[
            "SIMULATION: an exact classical simulation of the circuit; no quantum hardware is used.",
            "Search register: the m low bits of the nonce word W3; the rest of the header is a fixed template, so 2^m candidates (a real miner would search 32 + more bits).",
            "Construction: register-level constant propagation; round outputs T, e and a get fresh 32-qubit registers that are kept until the final uncompute; Sigma/sigma/Ch/Maj temporaries are uncomputed at once; Cuccaro adders (2n Toffoli, one ancilla); a constant is added through a prepared temporary register.",
            "Every compression is cut to `rounds` rounds; the target is the hash number's top d bits, read from H7 = IV7 + e(rounds - 4) of the outer compression (the early-reject identity).",
            "Diffusion is applied exactly (inversion about the mean over the search register); its gates are not subjected to noise.",
            "Noisy runs track the coherent state on a clean workspace exactly; an input left with garbage after an oracle call is treated as decohered (its probability set aside and counted as a random guess), which ignores any later re-interference of garbage branches.",
            "Noise: after each oracle gate, with probability p, a Pauli X or Z (equally likely) on one of the gate's qubits. Real amplitudes throughout (no Y errors).",
            "The phase flip's multi-controlled Z is counted as 2d - 3 Toffoli with ancillas.",
        ],
        baseline: "Random guess: success probability M / 2^m; classical search needs 2^m / M evaluations on average.",
        methodology: "Build the oracle circuit; run it on every input of the search register and compare with the reference hash; run Grover for the optimal number of iterations ideally and under noise for several error rates and trajectories; report exact gate and qubit counts per round count.",
        implementation: &["experiment_engine::grover_circuit"],
        dataset: "Template: nonce_atlas::synthetic(seed, 0) with its nonce field from the seed; noise: SplitMix64::stream(seed ^ trajectory tag, trajectory).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": if quick { json!([4, 8]) } else { json!([4, 5, 6, 8, 16, 32, 64]) },
        "search_bits": if quick { 6 } else { 8 },
        "noise_rounds": if quick { json!([4]) } else { json!([4, 8]) },
        // Trajectories x error rates x iterations multiply: noisy runs use a smaller register.
        "noise_search_bits": if quick { 4 } else { 6 },
        "error_rates": [1e-6, 1e-5, 1e-4, 1e-3],
        "trajectories": if quick { 4 } else { 24 },
        "reproduce": true,
    })
}

// ------------------------------------------------------------- circuit

type Q = u32;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Gate {
    X(Q),
    Cx(Q, Q),
    Ccx(Q, Q, Q),
}

/// A 32-bit word: classical, or 32 qubits (bit i in qubit `q[i]`).
#[derive(Clone, Debug)]
enum Word {
    C(u32),
    Q([Q; 32]),
}

#[derive(Clone, Copy)]
enum Bit {
    C(bool),
    Q(Q),
}

/// A literal for an AND: a constant, or a qubit possibly negated.
#[derive(Clone, Copy)]
enum Lit {
    C(bool),
    Q(Q, bool),
}

impl Word {
    fn bit(&self, i: usize) -> Bit {
        match self {
            Word::C(x) => Bit::C(x >> i & 1 == 1),
            Word::Q(q) => Bit::Q(q[i]),
        }
    }
}

#[derive(Clone, Copy)]
enum Temp {
    BigS0,
    BigS1,
    SmallS0,
    SmallS1,
}

impl Temp {
    /// (rotations, shift) of the function.
    fn spec(self) -> ([u32; 2], (u32, bool)) {
        match self {
            Temp::BigS0 => ([2, 13], (22, false)),
            Temp::BigS1 => ([6, 11], (25, false)),
            Temp::SmallS0 => ([7, 18], (3, true)),
            Temp::SmallS1 => ([17, 19], (10, true)),
        }
    }

    fn eval(self, x: u32) -> u32 {
        match self {
            Temp::BigS0 => big_sigma0(x),
            Temp::BigS1 => big_sigma1(x),
            Temp::SmallS0 => small_sigma0(x),
            Temp::SmallS1 => small_sigma1(x),
        }
    }
}

/// One summand of a new register.
enum Part {
    W(Word),
    Sigma(Temp, Word),
    Ch(Word, Word, Word),
    Maj(Word, Word, Word),
}

#[derive(Default)]
struct Circuit {
    gates: Vec<Gate>,
    qubits: Q,
    free: Vec<[Q; 32]>,
    free1: Vec<Q>,
}

impl Circuit {
    fn alloc(&mut self) -> [Q; 32] {
        self.free.pop().unwrap_or_else(|| {
            let base = self.qubits;
            self.qubits += 32;
            std::array::from_fn(|i| base + i as Q)
        })
    }

    fn alloc1(&mut self) -> Q {
        self.free1.pop().unwrap_or_else(|| {
            self.qubits += 1;
            self.qubits - 1
        })
    }

    fn xor_bit(&mut self, y: Q, b: Bit) {
        match b {
            Bit::C(true) => self.gates.push(Gate::X(y)),
            Bit::C(false) => {}
            Bit::Q(q) => self.gates.push(Gate::Cx(q, y)),
        }
    }

    /// Run `f` with a literal for a XOR b (computed in place on a's qubit and restored).
    fn with_xor(&mut self, a: Bit, b: Bit, f: impl FnOnce(&mut Self, Lit)) {
        match (a, b) {
            (Bit::C(x), Bit::C(y)) => f(self, Lit::C(x ^ y)),
            (Bit::Q(q), Bit::C(c)) | (Bit::C(c), Bit::Q(q)) => f(self, Lit::Q(q, c)),
            (Bit::Q(qa), Bit::Q(qb)) => {
                self.gates.push(Gate::Cx(qb, qa));
                f(self, Lit::Q(qa, false));
                self.gates.push(Gate::Cx(qb, qa));
            }
        }
    }

    /// y ^= p AND q.
    fn and_xor(&mut self, y: Q, p: Lit, q: Lit) {
        match (p, q) {
            (Lit::C(false), _) | (_, Lit::C(false)) => {}
            (Lit::C(true), Lit::C(true)) => self.gates.push(Gate::X(y)),
            (Lit::C(true), Lit::Q(a, neg)) | (Lit::Q(a, neg), Lit::C(true)) => {
                self.gates.push(Gate::Cx(a, y));
                if neg {
                    self.gates.push(Gate::X(y));
                }
            }
            (Lit::Q(a, na), Lit::Q(b, nb)) => {
                let flips: Vec<Q> = [(a, na), (b, nb)].into_iter().filter(|x| x.1).map(|x| x.0).collect();
                flips.iter().for_each(|&q| self.gates.push(Gate::X(q)));
                self.gates.push(Gate::Ccx(a, b, y));
                flips.iter().for_each(|&q| self.gates.push(Gate::X(q)));
            }
        }
    }

    fn lit(b: Bit) -> Lit {
        match b {
            Bit::C(c) => Lit::C(c),
            Bit::Q(q) => Lit::Q(q, false),
        }
    }

    /// XOR the value of a temporary into the zero register `y` (all gates self-inverse).
    fn compute_temp(&mut self, y: &[Q; 32], part: &Part) {
        for (i, &yi) in y.iter().enumerate() {
            match part {
                Part::W(w) => self.xor_bit(yi, w.bit(i)),
                Part::Sigma(t, x) => {
                    let (rots, (r3, shift)) = t.spec();
                    for r in rots {
                        self.xor_bit(yi, x.bit((i + r as usize) % 32));
                    }
                    let j = i + r3 as usize;
                    if !shift {
                        self.xor_bit(yi, x.bit(j % 32));
                    } else if j < 32 {
                        self.xor_bit(yi, x.bit(j));
                    }
                }
                Part::Ch(e, f, g) => {
                    self.xor_bit(yi, g.bit(i));
                    let ei = Self::lit(e.bit(i));
                    self.with_xor(f.bit(i), g.bit(i), |c, fg| c.and_xor(yi, ei, fg));
                }
                Part::Maj(a, b, cc) => {
                    self.xor_bit(yi, b.bit(i));
                    let (ai, bi, ci) = (a.bit(i), b.bit(i), cc.bit(i));
                    self.with_xor(ai, bi, |c, ab| c.with_xor(ci, bi, |c, cb| c.and_xor(yi, ab, cb)));
                }
            }
        }
    }

    /// dst += src (mod 2^32), Cuccaro ripple-carry adder; src unchanged.
    fn add_into(&mut self, dst: &[Q; 32], src: &Word) {
        let a = match src {
            Word::C(0) => return,
            Word::C(k) => {
                let r = self.alloc();
                (0..32).filter(|i| k >> i & 1 == 1).for_each(|i| self.gates.push(Gate::X(r[i])));
                self.add_into(dst, &Word::Q(r));
                (0..32).filter(|i| k >> i & 1 == 1).for_each(|i| self.gates.push(Gate::X(r[i])));
                self.free.push(r);
                return;
            }
            Word::Q(q) => *q,
        };
        let c = self.alloc1();
        let g = &mut self.gates;
        let mut maj3 = |x: Q, y: Q, z: Q| g.extend([Gate::Cx(z, y), Gate::Cx(z, x), Gate::Ccx(x, y, z)]);
        maj3(c, dst[0], a[0]);
        for i in 1..32 {
            maj3(a[i - 1], dst[i], a[i]);
        }
        let mut uma = |x: Q, y: Q, z: Q| g.extend([Gate::Ccx(x, y, z), Gate::Cx(z, x), Gate::Cx(x, y)]);
        for i in (1..32).rev() {
            uma(a[i - 1], dst[i], a[i]);
        }
        uma(c, dst[0], a[0]);
        self.free1.push(c);
    }

    /// A new register holding the sum of `parts` (classical when every part is).
    fn sum(&mut self, parts: Vec<Part>) -> Word {
        let classical = |w: &Word| matches!(w, Word::C(_));
        let value = |w: &Word| if let Word::C(x) = w { *x } else { 0 };
        let mut k = 0u32;
        let mut quantum = Vec::new();
        for p in parts {
            match &p {
                Part::W(w) if classical(w) => k = k.wrapping_add(value(w)),
                Part::Sigma(t, x) if classical(x) => k = k.wrapping_add(t.eval(value(x))),
                Part::Ch(e, f, g) if [e, f, g].iter().all(|w| classical(w)) => k = k.wrapping_add(ch(value(e), value(f), value(g))),
                Part::Maj(a, b, c) if [a, b, c].iter().all(|w| classical(w)) => k = k.wrapping_add(maj(value(a), value(b), value(c))),
                _ => quantum.push(p),
            }
        }
        if quantum.is_empty() {
            return Word::C(k);
        }
        let r = self.alloc();
        for (n, p) in quantum.iter().enumerate() {
            if n == 0 {
                self.compute_temp(&r, p);
                continue;
            }
            if let Part::W(w) = p {
                self.add_into(&r, w);
                continue;
            }
            let t = self.alloc();
            let start = self.gates.len();
            self.compute_temp(&t, p);
            let seg: Vec<Gate> = self.gates[start..].to_vec();
            self.add_into(&r, &Word::Q(t));
            self.gates.extend(seg.into_iter().rev());
            self.free.push(t);
        }
        self.add_into(&r, &Word::C(k));
        Word::Q(r)
    }

    fn compress(&mut self, mut s: [Word; 8], w: &mut Vec<Word>, rounds: std::ops::Range<usize>) -> [Word; 8] {
        for t in rounds {
            if t == w.len() {
                let word = self.sum(vec![Part::Sigma(Temp::SmallS1, w[t - 2].clone()), Part::W(w[t - 7].clone()), Part::Sigma(Temp::SmallS0, w[t - 15].clone()), Part::W(w[t - 16].clone())]);
                w.push(word);
            }
            let [a, b, c, d, e, f, g, h] = s;
            let t1 = self.sum(vec![Part::W(h), Part::Sigma(Temp::BigS1, e.clone()), Part::Ch(e.clone(), f.clone(), g.clone()), Part::W(Word::C(K[t])), Part::W(w[t].clone())]);
            let new_e = self.sum(vec![Part::W(d), Part::W(t1.clone())]);
            let new_a = self.sum(vec![Part::W(t1), Part::Sigma(Temp::BigS0, a.clone()), Part::Maj(a.clone(), b.clone(), c.clone())]);
            s = [new_a, a, b, c, new_e, e, f, g];
        }
        s
    }
}

/// The oracle's compute half for one template: returns the circuit and H7's word.
/// The search register is qubits 0..m of the W3 register (allocated first).
fn build(header: &[u8; 80], rounds: usize, m: u32) -> (Circuit, Word) {
    let hm = HeaderMidstate::with_rounds(header, rounds);
    let w3_const = u32::from_le_bytes(header[76..80].try_into().expect("4 bytes")).swap_bytes();
    let mut c = Circuit::default();
    let w3 = c.alloc();
    // High bits of W3 come from the template; the low m bits are searched (start in superposition).
    (m..32).filter(|&i| w3_const >> i & 1 == 1).for_each(|i| c.gates.push(Gate::X(w3[i as usize])));
    let mut w = vec![Word::C(hm.tail[0]), Word::C(hm.tail[1]), Word::C(hm.tail[2]), Word::Q(w3), Word::C(0x8000_0000)];
    w.resize(15, Word::C(0));
    w.push(Word::C(640));
    let s = c.compress(hm.state.map(Word::C), &mut w, 0..rounds);
    let mut w2: Vec<Word> = (0..8).map(|i| c.sum(vec![Part::W(Word::C(hm.state[i])), Part::W(s[i].clone())])).collect();
    w2.push(Word::C(0x8000_0000));
    w2.resize(15, Word::C(0));
    w2.push(Word::C(256));
    let s2 = c.compress(IV.map(Word::C), &mut w2, 0..rounds - 3);
    let h7 = c.sum(vec![Part::W(Word::C(IV[7])), Part::W(s2[4].clone())]);
    (c, h7)
}

/// Qubits of H7 holding the hash number's top `d` bits (MSB first).
fn target_qubits(h7: &[Q; 32], d: u32) -> Vec<Q> {
    (0..d as usize).map(|p| h7[(p / 8) * 8 + 7 - p % 8]).collect()
}

/// Reference: does the header with W3 = (template high bits | s) meet the d-bit target?
fn marked(header: &[u8; 80], rounds: usize, m: u32, s: u32, d: u32) -> (bool, u32) {
    let w3_const = u32::from_le_bytes(header[76..80].try_into().expect("4 bytes")).swap_bytes();
    let w3 = (w3_const >> m << m) | s;
    let nonce = w3.swap_bytes();
    let hm = HeaderMidstate::with_rounds(header, rounds);
    let h7 = hm.hash_words(nonce)[7];
    (h7.swap_bytes() >> (32 - d) == 0, h7)
}

// ------------------------------------------------------------- simulation

/// Real amplitudes over the search register with a clean workspace, and the
/// probability that decohered.
struct State {
    words: usize,
    amp: Vec<f64>,
    lost: f64,
}

fn get(row: &[u64], q: Q) -> bool {
    row[(q / 64) as usize] >> (q % 64) & 1 == 1
}

fn flip(row: &mut [u64], q: Q) {
    row[(q / 64) as usize] ^= 1 << (q % 64);
}

fn apply(row: &mut [u64], g: Gate) {
    match g {
        Gate::X(q) => flip(row, q),
        Gate::Cx(c, t) => {
            if get(row, c) {
                flip(row, t)
            }
        }
        Gate::Ccx(a, b, t) => {
            if get(row, a) && get(row, b) {
                flip(row, t)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Fault {
    /// Index into the oracle's gate sequence (compute, then uncompute).
    at: usize,
    qubit: Q,
    z: bool,
}

impl State {
    fn uniform(qubits: Q, m: u32) -> State {
        let n = 1usize << m;
        State { words: (qubits as usize).div_ceil(64), amp: vec![(n as f64).sqrt().recip(); n], lost: 0.0 }
    }

    /// Oracle: compute, phase flip on `target` all zero, uncompute; faults sorted by position.
    /// An input whose workspace is not clean afterwards has decohered: its probability moves to
    /// `lost`. One that comes back clean on another search value moves there.
    fn oracle(&mut self, gates: &[Gate], target: &[Q], faults: &[Fault]) {
        let (w, g) = (self.words, gates.len());
        let out: Vec<(Option<usize>, f64)> = self
            .amp
            .par_iter()
            .enumerate()
            .map(|(s, &a)| {
                if a == 0.0 {
                    return (None, 0.0);
                }
                let mut row = vec![0u64; w];
                row[0] = s as u64;
                let mut amp = a;
                let mut f = faults.iter().peekable();
                let mut step = |row: &mut [u64], amp: &mut f64, i: usize, gate: Gate| {
                    apply(row, gate);
                    while let Some(x) = f.next_if(|x| x.at == i) {
                        if x.z {
                            if get(row, x.qubit) {
                                *amp = -*amp;
                            }
                        } else {
                            flip(row, x.qubit);
                        }
                    }
                };
                for (i, &gate) in gates.iter().enumerate() {
                    step(&mut row, &mut amp, i, gate);
                }
                if target.iter().all(|&q| !get(&row, q)) {
                    amp = -amp;
                }
                for (i, &gate) in gates.iter().rev().enumerate() {
                    step(&mut row, &mut amp, g + i, gate);
                }
                let clean = (row[0] as usize) < self.amp.len() && row[1..].iter().all(|&x| x == 0);
                (clean.then_some(row[0] as usize), amp)
            })
            .collect();
        let mut next = vec![0.0; self.amp.len()];
        for (dst, a) in out {
            match dst {
                Some(d) => next[d] += a,
                None => self.lost += a * a,
            }
        }
        self.amp = next;
    }

    /// Inversion about the mean over the search register.
    fn diffuse(&mut self) {
        let mean = self.amp.iter().sum::<f64>() / self.amp.len() as f64;
        self.amp.iter_mut().for_each(|a| *a = 2.0 * mean - *a);
    }

    /// Probability that measuring the search register gives a marked value; decohered
    /// probability counts as a random guess.
    fn success(&self, marked: &[bool]) -> f64 {
        let hit: f64 = self.amp.iter().zip(marked).filter(|x| *x.1).map(|(a, _)| a * a).sum();
        let guess = marked.iter().filter(|&&x| x).count() as f64 / marked.len() as f64;
        hit + self.lost * guess
    }
}

/// Faults for one oracle call: geometric gaps with rate p over 2 * gates positions.
fn faults(rng: &mut SplitMix64, gates: &[Gate], p: f64) -> Vec<Fault> {
    let total = 2 * gates.len();
    let mut out = Vec::new();
    if p <= 0.0 {
        return out;
    }
    let mut at = 0usize;
    loop {
        let u = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        at += ((1.0 - u).ln() / (1.0 - p).ln()).floor() as usize;
        if at >= total {
            return out;
        }
        let gate = if at < gates.len() { gates[at] } else { gates[total - 1 - at] };
        let qs: Vec<Q> = match gate {
            Gate::X(a) => vec![a],
            Gate::Cx(a, b) => vec![a, b],
            Gate::Ccx(a, b, c) => vec![a, b, c],
        };
        out.push(Fault { at, qubit: qs[(rng.next_u32() % qs.len() as u32) as usize], z: rng.next_u32() & 1 == 1 });
        at += 1;
    }
}

fn counts(gates: &[Gate]) -> (u64, u64, u64) {
    gates.iter().fold((0, 0, 0), |(x, cx, ccx), g| match g {
        Gate::X(_) => (x + 1, cx, ccx),
        Gate::Cx(..) => (x, cx + 1, ccx),
        Gate::Ccx(..) => (x, cx, ccx + 1),
    })
}

/// A template header, its target bits d, which inputs are marked and every input's H7.
type Template = ([u8; 80], u32, Vec<bool>, Vec<u32>);

/// The template for (rounds, m): the synthetic header of `seed`, with the nonce field (from `seed`,
/// 64 variants of the W3 bits just above the searched ones) whose 2^m candidates hold a hit at the
/// largest d, fewest hits first. At 4 rounds H7 = K + W3, so a small window of W3 values can miss
/// every target or hit a short one many times. Returns the header and `choose_target`'s result.
fn template(seed: u64, rounds: usize, m: u32) -> Result<Template> {
    let mut best: Option<Template> = None;
    for salt in 0..64u32 {
        let mut header = crate::nonce_atlas::synthetic(seed, 0).header;
        let w3 = (seed as u32).swap_bytes() ^ salt << m;
        header[76..80].copy_from_slice(&w3.swap_bytes().to_le_bytes());
        let (d, table, h7) = choose_target(&header, rounds, m);
        let hits = table.iter().filter(|&&x| x).count();
        let better = |b: &Template| (d, std::cmp::Reverse(hits)) > (b.1, std::cmp::Reverse(b.2.iter().filter(|&&x| x).count()));
        if hits > 0 && best.as_ref().is_none_or(better) {
            best = Some((header, d, table, h7));
        }
    }
    best.with_context(|| format!("no template with a target hit among 2^{m} candidates at {rounds} rounds"))
}

/// Largest d <= m with at least one marked input, the marked table and every H7.
fn choose_target(header: &[u8; 80], rounds: usize, m: u32) -> (u32, Vec<bool>, Vec<u32>) {
    let h7: Vec<u32> = (0..1u32 << m).map(|s| marked(header, rounds, m, s, 1).1).collect();
    let mut d = m;
    loop {
        let table: Vec<bool> = h7.iter().map(|h| h.swap_bytes() >> (32 - d) == 0).collect();
        if table.iter().any(|&x| x) || d == 1 {
            return (d, table, h7);
        }
        d -= 1;
    }
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let m = p_u64(params, "search_bits")? as u32;
    anyhow::ensure!((2..=14).contains(&m) && rounds.iter().all(|&r| r >= 4), "need 2 <= search_bits <= 14 and rounds >= 4");
    let noise_rounds: Vec<usize> = params["noise_rounds"].as_array().map(|a| a.iter().filter_map(|x| x.as_u64().map(|x| x as usize)).collect()).unwrap_or_default();
    let rates: Vec<f64> = params["error_rates"].as_array().map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default();
    let trajectories = p_u64(params, "trajectories")?;
    let mn = p_u64(params, "noise_search_bits")? as u32;
    anyhow::ensure!((2..=10).contains(&mn), "need 2 <= noise_search_bits <= 10");
    let n = 1u64 << m;
    let mut rows = Vec::new();
    let mut summary = Vec::new();
    let mut all_ok = true;
    for &r in &rounds {
        let (header, d, table, reference) = template(seed, r, m)?;
        let (c, h7) = build(&header, r, m);
        let Word::Q(h7q) = h7 else { anyhow::bail!("H7 does not depend on the nonce at {r} rounds") };
        let marked_count = table.iter().filter(|&&x| x).count() as u64;
        let target = target_qubits(&h7q, d);
        // Gate-level check on every input: H7 register equals the reference, workspace cleans up.
        let words = (c.qubits as usize).div_ceil(64);
        let bad = (0..n as u32)
            .into_par_iter()
            .filter(|&s| {
                let mut row = vec![0u64; words];
                row[0] = s as u64;
                c.gates.iter().for_each(|&g| apply(&mut row, g));
                let got = (0..32).fold(0u32, |acc, i| acc | (get(&row, h7q[i]) as u32) << i);
                c.gates.iter().rev().for_each(|&g| apply(&mut row, g));
                let clean = row[0] == s as u64 && row[1..].iter().all(|&x| x == 0);
                got != reference[s as usize] || !clean
            })
            .count();
        all_ok &= bad == 0;
        // Ideal Grover with the optimal iteration count.
        let theta = (marked_count as f64 / n as f64).sqrt().asin();
        let k = ((std::f64::consts::PI / (4.0 * theta)) - 0.5).round().max(0.0) as usize;
        let theory = ((2 * k + 1) as f64 * theta).sin().powi(2);
        let mut st = State::uniform(c.qubits, m);
        for _ in 0..k {
            st.oracle(&c.gates, &target, &[]);
            st.diffuse();
        }
        let ideal = st.success(&table);
        all_ok &= (ideal - theory).abs() < 1e-9;
        // Noise, on a smaller search register (see noise_search_bits).
        let noisy: Value = if noise_rounds.contains(&r) {
            let (header_n, dn, table_n, _) = template(seed, r, mn)?;
            let (cn, h7n) = build(&header_n, r, mn);
            let Word::Q(h7nq) = h7n else { anyhow::bail!("H7 does not depend on the nonce at {r} rounds") };
            let mk = table_n.iter().filter(|&&x| x).count() as f64;
            let th = (mk / (1u64 << mn) as f64).sqrt().asin();
            let kn = ((std::f64::consts::PI / (4.0 * th)) - 0.5).round().max(0.0) as usize;
            let target_n = target_qubits(&h7nq, dn);
            let runs: Vec<Value> = rates
                .iter()
                .map(|&p| {
                    let runs: Vec<f64> = (0..trajectories)
                        .map(|tr| {
                            let mut rng = SplitMix64::stream(seed ^ 0x9015e ^ (r as u64) << 40 ^ p.to_bits(), tr);
                            let mut st = State::uniform(cn.qubits, mn);
                            for _ in 0..kn {
                                let f = faults(&mut rng, &cn.gates, p);
                                st.oracle(&cn.gates, &target_n, &f);
                                st.diffuse();
                            }
                            st.success(&table_n)
                        })
                        .collect();
                    let (mean, ci) = mean_ci95(&runs);
                    json!({ "error_rate": p, "success_mean": mean, "success_ci95": [ci.0, ci.1], "expected_faults": p * 2.0 * cn.gates.len() as f64 * kn as f64 })
                })
                .collect();
            json!({ "template_header": bitcoin_header::hex_encode(&header_n), "search_bits": mn, "target_bits": dn, "marked": mk, "iterations": kn,
                    "ideal_success": ((2 * kn + 1) as f64 * th).sin().powi(2), "random_guess": mk / (1u64 << mn) as f64, "by_error_rate": runs })
        } else {
            Value::Null
        };
        let (x, cx, ccx) = counts(&c.gates);
        let toffoli_per_iteration = 2 * ccx + (2 * d as u64).saturating_sub(3);
        let guess = marked_count as f64 / n as f64;
        summary.push(format!(
            "{r} rounds: {} qubits, {ccx} Toffoli + {cx} CNOT + {x} X per oracle half ({toffoli_per_iteration} Toffoli per Grover iteration); circuit {} on all {n} inputs; d = {d}, {marked_count} marked; {k} iterations: success {ideal:.4} (theory {theory:.4}, random guess {guess:.4}){}.",
            c.qubits,
            if bad == 0 { "correct" } else { "WRONG" },
            if noisy.is_null() {
                String::new()
            } else {
                format!("; with {} search bits (ideal {:.3}, guess {:.3}) under noise: {}", noisy["search_bits"], noisy["ideal_success"].as_f64().unwrap_or(0.0), noisy["random_guess"].as_f64().unwrap_or(0.0),
                    noisy["by_error_rate"].as_array().into_iter().flatten().map(|v| format!("p = {:.0e} gives {:.3}", v["error_rate"].as_f64().unwrap_or(0.0), v["success_mean"].as_f64().unwrap_or(0.0))).collect::<Vec<_>>().join(", "))
            }
        ));
        rows.push(json!({
            "rounds": r, "template_header": bitcoin_header::hex_encode(&header), "qubits": c.qubits, "gates_per_half": { "x": x, "cnot": cx, "toffoli": ccx }, "toffoli_per_iteration": toffoli_per_iteration,
            "t_gates_per_iteration": 7 * toffoli_per_iteration, "circuit_check": { "inputs": n, "failures": bad },
            "target_bits": d, "marked": marked_count, "iterations": k, "ideal_success": ideal, "theory_success": theory, "random_guess": guess, "noisy": noisy,
        }));
    }
    // Noise threshold: the rate at which success falls to twice the random guess, per noisy round count.
    let full = rows.iter().find(|r| r["rounds"] == 64).cloned();
    if let Some(f) = &full {
        let t = f["toffoli_per_iteration"].as_f64().unwrap_or(0.0);
        let iters80 = std::f64::consts::PI / 4.0 * 2f64.powi(40);
        summary.push(format!("Full SHA256d oracle: {:.3e} Toffoli per iteration in this construction (quantum-model estimated 1.47e5). A d = 80 search needs {iters80:.2e} serial iterations, {:.2e} Toffoli: an error per gate well below 1/{:.1e} is needed to keep the amplitude.",
            t, t * iters80, t * iters80));
    }
    let obs = json!({ "search_bits": m, "by_rounds": rows, "all_checks_passed": all_ok });
    let mut o = Outcome::new(obs.clone(), obs, vec![], summary);
    o.result = Some(if all_ok { "exact-analysis" } else { "error" });
    Ok(o)
}

/// Rebuild the smallest circuit and check it on every input with a second
/// evaluator: the reference SHA-256 from `verification::independent`.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let m = p_u64(params, "search_bits")? as u32;
    let mut header = crate::nonce_atlas::synthetic(seed, 0).header;
    header[76..80].copy_from_slice(&(seed as u32).to_le_bytes());
    let ind = verification::independent::Sha256::default();
    let mut problems = Vec::new();
    if outcome.observations["all_checks_passed"] != true {
        problems.push("a circuit check or the ideal Grover comparison failed".to_string());
    }
    for r in p_rounds(params)?.into_iter().take(2) {
        for s in 0..1u32 << m {
            let (_, h7) = marked(&header, r, m, s, 1);
            let w3_const = u32::from_le_bytes(header[76..80].try_into().expect("4 bytes")).swap_bytes();
            let mut h = header;
            h[76..80].copy_from_slice(&((w3_const >> m << m) | s).swap_bytes().to_le_bytes());
            let digest = ind.sha256d(&h, r);
            if u32::from_be_bytes(digest[28..32].try_into().expect("4 bytes")) != h7 {
                problems.push(format!("{r} rounds: reference H7 differs from the independent SHA-256 at s = {s}"));
                break;
            }
        }
    }
    Ok(Verification {
        method: "the reference H7 used to check every circuit is recomputed with verification::independent for every input at the first two round counts; the circuit checks and ideal-vs-theory comparison of the run must all pass".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "independent hashes agree; every circuit check passed".into() } else { problems.join("; ") },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cuccaro adder, Sigma, Ch and Maj on basis states against the reference functions.
    #[test]
    fn gadgets_match_reference() {
        let mut rng = SplitMix64::stream(5, 0);
        for _ in 0..32 {
            let (x, y, z, k): (u32, u32, u32, u32) = (rng.next_u32(), rng.next_u32(), rng.next_u32(), rng.next_u32());
            let mut c = Circuit::default();
            let (a, b, e) = (c.alloc(), c.alloc(), c.alloc());
            let prep: Vec<Gate> = [(a, x), (b, y), (e, z)].iter().flat_map(|(r, v)| (0..32).filter(move |i| v >> i & 1 == 1).map(move |i| Gate::X(r[i]))).collect();
            c.gates.extend(prep);
            let s = c.sum(vec![Part::W(Word::Q(a)), Part::Sigma(Temp::BigS1, Word::Q(b)), Part::Ch(Word::Q(a), Word::Q(b), Word::Q(e)), Part::Maj(Word::Q(e), Word::Q(a), Word::C(k)), Part::W(Word::C(k))]);
            let Word::Q(sq) = s else { panic!("quantum sum") };
            let mut row = vec![0u64; (c.qubits as usize).div_ceil(64)];
            c.gates.iter().for_each(|&g| apply(&mut row, g));
            let got = (0..32).fold(0u32, |acc, i| acc | (get(&row, sq[i]) as u32) << i);
            let want = x.wrapping_add(big_sigma1(y)).wrapping_add(ch(x, y, z)).wrapping_add(maj(z, x, k)).wrapping_add(k);
            assert_eq!(got, want);
            let read = |r: &[Q; 32]| (0..32).fold(0u32, |acc, i| acc | (get(&row, r[i]) as u32) << i);
            assert_eq!((read(&a), read(&b), read(&e)), (x, y, z), "inputs restored");
        }
    }
}
