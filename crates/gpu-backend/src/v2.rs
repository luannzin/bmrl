//! Generated kernels: v2 (one header per nonce) and v3 (k version-rolled
//! headers per nonce). The CPU kernel's tricks in WGSL, as straight-line code.
//!
//! * The host passes each header's second-block state after rounds 0..=2
//!   (`pre`), so the nonce enters at round 3 of a precomputed state.
//! * Every round and schedule word is unrolled with K, the padding words and
//!   the outer IV as literals. Constant terms are folded here, and terms that
//!   do not depend on the nonce (W16, W17, most of round 3) come first in each
//!   sum, so the driver computes them once on the scalar unit. Nothing is an
//!   array, so the state stays in registers.
//! * The outer compression stops after round 60: H7 = IV7 + e60 holds the
//!   most significant 32 bits of the hash number. Only a nonce whose top word
//!   passes is hashed in full (`full_hash`) and compared with the whole target.
//!   The values the early check never reads (a in outer rounds 57..=60,
//!   W61..W63) are dead code for the driver.
//! * With k > 1 (v3, overt AsicBoost), the k headers differ only in BIP320
//!   version bits: their second blocks are identical, so the inner message
//!   schedule is computed once per nonce and the k inner compressions run in
//!   lockstep on it. `experiment_engine::work_sharing` counts the saving.
//!
//! Output is bit-identical to `gpu/wgsl/sha256d.wgsl` (v1) and the CPU kernels.

use sha256_core::{IV, K, small_sigma0, small_sigma1};
use std::fmt::Write;

/// A message-schedule word as the shader sees it.
#[derive(Clone)]
enum Word {
    Const(u32),
    /// Same value for every nonce of the dispatch.
    Uniform(String),
    Nonce(String),
}

/// Bind `name` to the sum of `terms`: constants folded, nonce-independent
/// terms first. A sum of constants is folded entirely and emits nothing.
fn bind(out: &mut String, name: String, terms: impl IntoIterator<Item = Word>) -> Word {
    let (mut k, mut uniform, mut nonce) = (0u32, Vec::new(), Vec::new());
    for t in terms {
        match t {
            Word::Const(x) => k = k.wrapping_add(x),
            Word::Uniform(s) => uniform.push(s),
            Word::Nonce(s) => nonce.push(s),
        }
    }
    if uniform.is_empty() && nonce.is_empty() {
        return Word::Const(k);
    }
    let per_nonce = !nonce.is_empty();
    let literal = (k != 0).then(|| format!("{k:#010x}u"));
    let expr: Vec<String> = uniform.into_iter().chain(literal).chain(nonce).collect();
    writeln!(out, "        let {name} = {};", expr.join(" + ")).unwrap();
    if per_nonce { Word::Nonce(name) } else { Word::Uniform(name) }
}

fn sigma(w: &Word, f: fn(u32) -> u32, wgsl: &str) -> Word {
    match w {
        Word::Const(x) => Word::Const(f(*x)),
        Word::Uniform(s) => Word::Uniform(format!("{wgsl}({s})")),
        Word::Nonce(s) => Word::Nonce(format!("{wgsl}({s})")),
    }
}

/// Rounds `rounds` of one compression for every state in `states`, all on the
/// same message: `w` starts with the 16 message words and grows by one
/// schedule word (named `{wp}w{t}`) just before the round that needs it.
/// State `m`'s values are named with prefix `sp[m]`.
fn compress(out: &mut String, wp: &str, sp: &[String], states: &mut [[String; 8]], w: &mut Vec<Word>, rounds: std::ops::Range<usize>) {
    for t in rounds {
        if t == w.len() {
            let terms = [sigma(&w[t - 2], small_sigma1, "ssig1"), w[t - 7].clone(), sigma(&w[t - 15], small_sigma0, "ssig0"), w[t - 16].clone()];
            let word = bind(out, format!("{wp}w{t}"), terms);
            w.push(word);
        }
        let kw = match &w[t] {
            Word::Const(x) => format!("{:#010x}u", K[t].wrapping_add(*x)),
            Word::Uniform(x) | Word::Nonce(x) => format!("{:#010x}u + {x}", K[t]),
        };
        for (p, s) in sp.iter().zip(states.iter_mut()) {
            let [a, b, c, d, e, f, g, h] = s.clone();
            writeln!(out, "        let {p}t{t} = {h} + bsig1({e}) + ch({e}, {f}, {g}) + {kw};").unwrap();
            writeln!(out, "        let {p}e{t} = {d} + {p}t{t};").unwrap();
            writeln!(out, "        let {p}a{t} = {p}t{t} + bsig0({a}) + maj({a}, {b}, {c});").unwrap();
            *s = [format!("{p}a{t}"), a, b, c, format!("{p}e{t}"), e, f, g];
        }
    }
}

/// Outer compression of member `m` through round `outer_rounds - 1`, from its
/// inner state `s`; returns the outer working state (not fed forward).
fn outer(out: &mut String, m: usize, s: &[String; 8], outer_rounds: usize) -> [String; 8] {
    let mut w2 = Vec::new();
    for (i, x) in s.iter().enumerate() {
        w2.push(bind(out, format!("d{m}_{i}"), [Word::Uniform(format!("mid{m}_{i}")), Word::Nonce(x.clone())]));
    }
    w2.push(Word::Const(0x8000_0000));
    w2.resize(15, Word::Const(0));
    w2.push(Word::Const(256));
    let p = format!("o{m}_");
    let mut s2 = [IV.map(|x| format!("{x:#010x}u"))];
    compress(out, &p, std::slice::from_ref(&p), &mut s2, &mut w2, 0..outer_rounds);
    let [s2] = s2;
    s2
}

/// Inner compressions of `k` members in lockstep on the shared second block.
fn inner(out: &mut String, k: usize) -> Vec<[String; 8]> {
    let mut w = vec![Word::Uniform("w0".into()), Word::Uniform("w1".into()), Word::Uniform("w2".into()), Word::Nonce("w3".into()), Word::Const(0x8000_0000)];
    w.resize(15, Word::Const(0));
    w.push(Word::Const(640));
    let sp: Vec<String> = (0..k).map(|m| format!("i{m}_")).collect();
    let mut states: Vec<[String; 8]> = (0..k).map(|m| std::array::from_fn(|i| format!("pre{m}_{i}"))).collect();
    compress(out, "i", &sp, &mut states, &mut w, 3..64);
    states
}

const TEMPLATE: &str = r#"// SHA-256d nonce search, generated by crates/gpu-backend/src/v2.rs with
// MEMBERS version-rolled headers per nonce; edit the generator, not this text.
// Same bindings as gpu/wgsl/sha256d.wgsl (v1). Hits are (nonce, member) pairs.

struct Member {
    mid: array<u32, 8>,
    // Second-block state after rounds 0..=2.
    pre: array<u32, 8>,
}

struct Params {
    midstate: array<u32, 8>,
    tail: array<u32, 4>,
    target_be: array<u32, 8>,
    nonce_base: u32,
    count: u32,
    per_invocation: u32,
    stride: u32,
    capacity: u32,
    pad0: u32,
    pad1: u32,
    pad2: u32,
    members: array<Member, MEMBERS>,
}

struct Found {
    count: atomic<u32>,
    nonces: array<u32>,
}

@group(0) @binding(0) var<storage, read> params: Params;
@group(0) @binding(1) var<storage, read_write> found: Found;
@group(0) @binding(2) var<storage, read_write> dump: array<u32>;

fn bsig0(x: u32) -> u32 { return ((x >> 2u) | (x << 30u)) ^ ((x >> 13u) | (x << 19u)) ^ ((x >> 22u) | (x << 10u)); }
fn bsig1(x: u32) -> u32 { return ((x >> 6u) | (x << 26u)) ^ ((x >> 11u) | (x << 21u)) ^ ((x >> 25u) | (x << 7u)); }
fn ssig0(x: u32) -> u32 { return ((x >> 7u) | (x << 25u)) ^ ((x >> 18u) | (x << 14u)) ^ (x >> 3u); }
fn ssig1(x: u32) -> u32 { return ((x >> 17u) | (x << 15u)) ^ ((x >> 19u) | (x << 13u)) ^ (x >> 10u); }
// Both are bit selects (one v_bfi_b32 on AMD).
fn ch(e: u32, f: u32, g: u32) -> u32 { return (e & f) | (~e & g); }
fn maj(a: u32, b: u32, c: u32) -> u32 { let x = a ^ b; return (x & c) | (~x & b); }

fn bswap(x: u32) -> u32 {
    return (x << 24u) | ((x & 0xff00u) << 8u) | ((x >> 8u) & 0xff00u) | (x >> 24u);
}

// Full SHA-256d (H0..H7) of member `m`'s header with `nonce`.
fn full_hash(nonce: u32, m: u32) -> array<u32, 8> {
//FULL
}

// The hash is a little-endian 256-bit number: its most significant word is bswap(H7).
fn meets_target(hash: array<u32, 8>) -> bool {
    var h = hash;
    for (var i = 0u; i < 8u; i++) {
        let v = bswap(h[7u - i]);
        let t = params.target_be[i];
        if (v < t) {
            return true;
        }
        if (v > t) {
            return false;
        }
    }
    return true;
}

fn record(nonce: u32, m: u32) {
    let slot = atomicAdd(&found.count, 1u);
    if (slot < params.capacity) {
        found.nonces[2u * slot] = nonce;
        found.nonces[2u * slot + 1u] = m;
    }
}

@compute @workgroup_size(256)
fn search(@builtin(global_invocation_id) gid: vec3<u32>) {
//UNIFORMS
    let target0 = params.target_be[0];
    for (var j = 0u; j < params.per_invocation; j++) {
        let offset = j * params.stride + gid.x;
        if (offset >= params.count) {
            break;
        }
        let nonce = params.nonce_base + offset;
        let w3 = bswap(nonce);
//EARLY
    }
}

@compute @workgroup_size(256)
fn dump_hashes(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x >= params.count) {
        return;
    }
    let h = full_hash(params.nonce_base + gid.x, 0u);
    for (var k = 0u; k < 8u; k++) {
        dump[gid.x * 8u + k] = h[k];
    }
}
"#;

/// Loads of the per-dispatch constants; member `m`'s are read from `members[{index(m)}]`.
fn uniforms(k: usize, index: impl Fn(usize) -> String) -> String {
    let mut u = String::new();
    for m in 0..k {
        for i in 0..8 {
            writeln!(u, "    let mid{m}_{i} = params.members[{}].mid[{i}];", index(m)).unwrap();
            writeln!(u, "    let pre{m}_{i} = params.members[{}].pre[{i}];", index(m)).unwrap();
        }
    }
    for i in 0..3 {
        writeln!(u, "    let w{i} = params.tail[{i}];").unwrap();
    }
    u
}

/// The WGSL source for `k` version-rolled headers per nonce (k = 1 is v2).
pub fn shader(k: usize) -> String {
    assert!(k >= 1, "at least one header per nonce");
    let mut full = uniforms(1, |_| "m".into());
    writeln!(full, "        let w3 = bswap(nonce);").unwrap();
    let s = inner(&mut full, 1);
    let s2 = outer(&mut full, 0, &s[0], 64);
    let digest: Vec<String> = (0..8).map(|i| format!("{:#010x}u + {}", IV[i], s2[i])).collect();
    writeln!(full, "        return array<u32, 8>({});", digest.join(", ")).unwrap();

    let mut early = String::new();
    let states = inner(&mut early, k);
    for (m, s) in states.iter().enumerate() {
        let s2 = outer(&mut early, m, s, 61);
        // H7 = IV7 + e60 is the most significant word of the hash number.
        writeln!(early, "        if (bswap({:#010x}u + {}) <= target0 && meets_target(full_hash(nonce, {m}u))) {{", IV[7], s2[4]).unwrap();
        writeln!(early, "            record(nonce, {m}u);").unwrap();
        writeln!(early, "        }}").unwrap();
    }

    TEMPLATE
        .replace("MEMBERS", &k.to_string())
        .replace("//UNIFORMS", &uniforms(k, |m| format!("{m}u")))
        .replace("//FULL", &full)
        .replace("//EARLY", &early)
}
