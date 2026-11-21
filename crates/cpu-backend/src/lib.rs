//! CPU nonce search.
//!
//! Kernels, slowest to fastest:
//! * `Midstate` — cached first block, generic compression for the rest.
//! * `Scalar` — midstate plus nonce-independent precomputation (rounds 0..2
//!   of the second block and schedule words W16, W17) and an early reject
//!   after round 60 of the outer hash: the final word H7 equals
//!   `IV[7] + e_60`, and H7 holds the most significant 32 bits of the hash
//!   number, so most nonces are rejected three rounds early.
//! * `Avx2` — the `Scalar` algorithm on 8 nonces per instruction
//!   (x86-64 AVX2, detected at runtime).
//!
//! Every candidate that passes the early check is confirmed with the full
//! scalar computation, so kernels can only differ in speed, never in result.

use bitcoin_header::hash_number_words;
use mining_engine::{Backend, Scan, Work};
use rayon::prelude::*;
use sha256_core::{IV, K, ROUNDS, State, feed_forward, round, small_sigma0, small_sigma1};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    Midstate,
    Scalar,
    Avx2,
}

impl Kernel {
    pub const ALL: [Kernel; 3] = [Kernel::Midstate, Kernel::Scalar, Kernel::Avx2];

    pub fn name(self) -> &'static str {
        match self {
            Kernel::Midstate => "midstate",
            Kernel::Scalar => "scalar",
            Kernel::Avx2 => "avx2",
        }
    }

    pub fn available(self) -> bool {
        match self {
            Kernel::Avx2 => avx2_available(),
            _ => true,
        }
    }

    /// Fastest kernel this CPU supports.
    pub fn best() -> Kernel {
        if avx2_available() { Kernel::Avx2 } else { Kernel::Scalar }
    }

    pub fn parse(s: &str) -> Option<Kernel> {
        Kernel::ALL.into_iter().find(|k| k.name() == s)
    }
}

fn avx2_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[inline(always)]
fn schedule_word(w: &[u32; 64], t: usize) -> u32 {
    small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16])
}

/// Per-work precomputation shared by the `Scalar` and `Avx2` kernels.
#[derive(Clone, Debug)]
pub struct Prepared {
    mid: State,
    /// Second-block message words with the nonce slot (W3) zeroed.
    w: [u32; 16],
    /// State after rounds 0..=2 of the second block (W3 enters at round 3).
    pre: State,
    w16: u32,
    w17: u32,
    /// Target as big-endian words, most significant first.
    target: [u32; 8],
}

impl Prepared {
    pub fn new(work: &Work) -> Self {
        assert_eq!(work.midstate.rounds, ROUNDS, "production kernels are full-round only");
        let mut w = work.midstate.second_block(0);
        w[3] = 0;
        // W16 = σ1(W14) + W9 + σ0(W1) + W0 and W17 = σ1(W15) + W10 + σ0(W2) + W1
        // with W9 = W10 = W14 = 0: neither touches W3.
        let w16 = small_sigma0(w[1]).wrapping_add(w[0]);
        let w17 = small_sigma1(w[15]).wrapping_add(small_sigma0(w[2])).wrapping_add(w[1]);
        let mut pre = work.midstate.state;
        for t in 0..3 {
            pre = round(&pre, K[t], w[t]);
        }
        Self { mid: work.midstate.state, w, pre, w16, w17, target: work.target.words() }
    }

    #[inline(always)]
    fn inner_schedule(&self, nonce: u32) -> [u32; 64] {
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(&self.w);
        w[3] = nonce.swap_bytes();
        w[16] = self.w16;
        w[17] = self.w17;
        for t in 18..64 {
            w[t] = schedule_word(&w, t);
        }
        w
    }

    #[inline(always)]
    fn outer_schedule(&self, nonce: u32) -> [u32; 64] {
        let w = self.inner_schedule(nonce);
        let mut s = self.pre;
        for t in 3..64 {
            s = round(&s, K[t], w[t]);
        }
        let inner = feed_forward(&self.mid, &s);
        let mut w2 = [0u32; 64];
        w2[..8].copy_from_slice(&inner);
        w2[8] = 0x8000_0000;
        w2[15] = 256;
        for t in 16..64 {
            w2[t] = schedule_word(&w2, t);
        }
        w2
    }

    /// Full SHA-256d state words for `nonce` (no early exit).
    pub fn hash_words(&self, nonce: u32) -> State {
        let w2 = self.outer_schedule(nonce);
        let mut s = IV;
        for t in 0..64 {
            s = round(&s, K[t], w2[t]);
        }
        feed_forward(&IV, &s)
    }

    /// Does `nonce` meet the target? Rejects after round 60 when H7 is too big.
    #[inline]
    pub fn check(&self, nonce: u32) -> bool {
        let w2 = self.outer_schedule(nonce);
        let mut s = IV;
        for t in 0..61 {
            s = round(&s, K[t], w2[t]);
        }
        // h after round 63 is e after round 60.
        if IV[7].wrapping_add(s[4]).swap_bytes() > self.target[0] {
            return false;
        }
        for t in 61..64 {
            s = round(&s, K[t], w2[t]);
        }
        hash_number_words(&feed_forward(&IV, &s)) <= self.target
    }
}

/// Scan `count` nonces from `start` on the current thread.
pub fn scan_range(kernel: Kernel, p: &Prepared, work: &Work, start: u32, count: u32, out: &mut Vec<u32>) {
    match kernel {
        Kernel::Midstate => {
            let target = work.target.words();
            for i in 0..count {
                let nonce = start.wrapping_add(i);
                if hash_number_words(&work.midstate.hash_words(nonce)) <= target {
                    out.push(nonce);
                }
            }
        }
        Kernel::Scalar => {
            for i in 0..count {
                let nonce = start.wrapping_add(i);
                if p.check(nonce) {
                    out.push(nonce);
                }
            }
        }
        Kernel::Avx2 => {
            assert!(avx2_available(), "AVX2 kernel requested on a CPU without AVX2");
            let groups = count / 8;
            #[cfg(target_arch = "x86_64")]
            // SAFETY: AVX2 support was checked above.
            unsafe {
                avx2::scan(p, start, groups, out)
            };
            for i in groups * 8..count {
                let nonce = start.wrapping_add(i);
                if p.check(nonce) {
                    out.push(nonce);
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::Prepared;
    use sha256_core::{IV, K};
    use std::arch::x86_64::*;

    type V = __m256i;

    #[inline]
    #[target_feature(enable = "avx2")]
    fn splat(x: u32) -> V {
        _mm256_set1_epi32(x as i32)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn add(a: V, b: V) -> V {
        _mm256_add_epi32(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn xor(a: V, b: V) -> V {
        _mm256_xor_si256(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn and(a: V, b: V) -> V {
        _mm256_and_si256(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn or(a: V, b: V) -> V {
        _mm256_or_si256(a, b)
    }
    /// `!a & b`
    #[inline]
    #[target_feature(enable = "avx2")]
    fn andnot(a: V, b: V) -> V {
        _mm256_andnot_si256(a, b)
    }

    macro_rules! rotr {
        ($x:expr, $n:literal) => {
            or(_mm256_srli_epi32::<$n>($x), _mm256_slli_epi32::<{ 32 - $n }>($x))
        };
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn bsig0(x: V) -> V {
        xor(xor(rotr!(x, 2), rotr!(x, 13)), rotr!(x, 22))
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn bsig1(x: V) -> V {
        xor(xor(rotr!(x, 6), rotr!(x, 11)), rotr!(x, 25))
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn ssig0(x: V) -> V {
        xor(xor(rotr!(x, 7), rotr!(x, 18)), _mm256_srli_epi32::<3>(x))
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    fn ssig1(x: V) -> V {
        xor(xor(rotr!(x, 17), rotr!(x, 19)), _mm256_srli_epi32::<10>(x))
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn round(s: &mut [V; 8], k: u32, w: V) {
        let [a, b, c, d, e, f, g, h] = *s;
        let ch = xor(and(e, f), andnot(e, g));
        let maj = or(and(a, b), and(c, or(a, b)));
        let t1 = add(add(add(h, bsig1(e)), add(ch, splat(k))), w);
        let t2 = add(bsig0(a), maj);
        *s = [add(t1, t2), a, b, c, add(d, t1), e, f, g];
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn schedule(w: &mut [V; 64], from: usize) {
        for t in from..64 {
            w[t] = add(add(ssig1(w[t - 2]), w[t - 7]), add(ssig0(w[t - 15]), w[t - 16]));
        }
    }

    /// Scan `groups * 8` nonces from `start`.
    #[target_feature(enable = "avx2")]
    pub fn scan(p: &Prepared, start: u32, groups: u32, out: &mut Vec<u32>) {
        let bswap = _mm256_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
        let lanes = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
        let zero = _mm256_setzero_si256();
        let (mut mid, mut pre, mut iv) = ([zero; 8], [zero; 8], [zero; 8]);
        for i in 0..8 {
            mid[i] = splat(p.mid[i]);
            pre[i] = splat(p.pre[i]);
            iv[i] = splat(IV[i]);
        }
        let mut w_template = [zero; 64];
        for i in 0..16 {
            w_template[i] = splat(p.w[i]);
        }
        w_template[16] = splat(p.w16);
        w_template[17] = splat(p.w17);
        let iv7 = splat(IV[7]);

        for g in 0..groups {
            let base = start.wrapping_add(g * 8);
            let mut w = w_template;
            w[3] = _mm256_shuffle_epi8(add(splat(base), lanes), bswap);
            schedule(&mut w, 18);
            let mut s = pre;
            for t in 3..64 {
                round(&mut s, K[t], w[t]);
            }
            let mut w2 = [zero; 64];
            for i in 0..8 {
                w2[i] = add(mid[i], s[i]);
            }
            w2[8] = splat(0x8000_0000);
            w2[15] = splat(256);
            schedule(&mut w2, 16);
            let mut s2 = iv;
            for t in 0..61 {
                round(&mut s2, K[t], w2[t]);
            }
            // SAFETY: __m256i and [u32; 8] have identical size; every bit pattern is valid.
            let h7: [u32; 8] = unsafe { std::mem::transmute(add(s2[4], iv7)) };
            for (lane, h) in h7.iter().enumerate() {
                if h.swap_bytes() <= p.target[0] {
                    let nonce = base.wrapping_add(lane as u32);
                    if p.check(nonce) {
                        out.push(nonce);
                    }
                }
            }
        }
    }
}

/// Multi-threaded CPU backend.
pub struct CpuBackend {
    kernel: Kernel,
    threads: usize,
    pool: rayon::ThreadPool,
}

/// Nonces per parallel work item.
pub const CHUNK: u64 = 1 << 16;

impl CpuBackend {
    /// `threads == 0` uses every logical CPU.
    pub fn new(kernel: Kernel, threads: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(kernel.available(), "kernel {} is not supported on this CPU", kernel.name());
        let threads = if threads == 0 { std::thread::available_parallelism().map_or(1, |n| n.get()) } else { threads };
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
        Ok(Self { kernel, threads, pool })
    }

    pub fn kernel(&self) -> Kernel {
        self.kernel
    }

    pub fn threads(&self) -> usize {
        self.threads
    }
}

impl Backend for CpuBackend {
    fn name(&self) -> String {
        format!("cpu-{} x{}", self.kernel.name(), self.threads)
    }

    fn scan(&self, work: &Work, start: u32, count: u64, max_found: usize) -> anyhow::Result<Scan> {
        anyhow::ensure!(start as u64 + count <= 1 << 32, "nonce range exceeds 2^32");
        let p = Prepared::new(work);
        let end = start as u64 + count;
        let (stop, hits, hashes) = (AtomicBool::new(false), AtomicUsize::new(0), AtomicU64::new(0));
        let mut found: Vec<u32> = self.pool.install(|| {
            (0..count.div_ceil(CHUNK))
                .into_par_iter()
                .flat_map_iter(|c| {
                    let mut local = Vec::new();
                    if !stop.load(Relaxed) {
                        let s = start as u64 + c * CHUNK;
                        let n = CHUNK.min(end - s);
                        scan_range(self.kernel, &p, work, s as u32, n as u32, &mut local);
                        hashes.fetch_add(n, Relaxed);
                        if !local.is_empty() && hits.fetch_add(local.len(), Relaxed) + local.len() >= max_found {
                            stop.store(true, Relaxed);
                        }
                    }
                    local
                })
                .collect()
        });
        found.sort_unstable();
        Ok(Scan { found, hashes: hashes.into_inner() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mining_engine::{ReferenceBackend, scan_verified, synthetic_work};

    #[test]
    fn prepared_hash_matches_reference_midstate() {
        let work = synthetic_work(3, 0);
        let p = Prepared::new(&work);
        for nonce in [0u32, 1, 0x1234_5678, u32::MAX, 0x8000_0000] {
            assert_eq!(p.hash_words(nonce), work.midstate.hash_words(nonce), "nonce {nonce:#x}");
        }
    }

    #[test]
    fn all_kernels_agree_with_reference() {
        for (seed, bits) in [(1u32, 8u32), (2, 1), (3, 12)] {
            let work = synthetic_work(seed, bits);
            let reference = ReferenceBackend.scan(&work, 1000, 20_003, usize::MAX).unwrap();
            for kernel in Kernel::ALL.into_iter().filter(|k| k.available()) {
                for threads in [1, 4] {
                    let b = CpuBackend::new(kernel, threads).unwrap();
                    let scan = scan_verified(&b, &work, 1000, 20_003).unwrap();
                    assert_eq!(scan, reference, "{} seed {seed} bits {bits}", b.name());
                }
            }
        }
    }

    #[test]
    fn range_end_of_nonce_space() {
        let work = synthetic_work(4, 2);
        let start = u32::MAX - 100;
        let reference = ReferenceBackend.scan(&work, start, 101, usize::MAX).unwrap();
        let b = CpuBackend::new(Kernel::best(), 2).unwrap();
        assert_eq!(b.scan(&work, start, 101, usize::MAX).unwrap(), reference);
        assert!(b.scan(&work, start, 102, usize::MAX).is_err());
    }

    #[test]
    fn stops_early_when_enough_hits() {
        let work = synthetic_work(5, 1);
        let b = CpuBackend::new(Kernel::best(), 2).unwrap();
        let scan = b.scan(&work, 0, 1 << 24, 1).unwrap();
        assert!(!scan.found.is_empty() && scan.hashes < 1 << 24);
    }
}
