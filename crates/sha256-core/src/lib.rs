//! SHA-256 implemented directly from FIPS 180-4.
//!
//! All arithmetic is explicit 32-bit modular arithmetic (`wrapping_add`,
//! `rotate_right`). The compression function takes a round count so the same
//! code serves full SHA-256 (64 rounds) and reduced-round research variants.
//! A reduced-round result is *not* a SHA-256 result; callers must label it.
//!
//! Tracing exposes the full message schedule and the working state after
//! every round for mathematical analysis.

#![forbid(unsafe_code)]

/// Number of rounds in the standard compression function.
pub const ROUNDS: usize = 64;

/// Chaining value / working state: eight 32-bit words `a..h`.
pub type State = [u32; 8];

/// Round constants (FIPS 180-4 §4.2.2).
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash value (FIPS 180-4 §5.3.3).
pub const IV: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline(always)]
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
pub fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
pub fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
pub fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
pub fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Split a 64-byte block into 16 big-endian words.
pub fn block_words(block: &[u8; 64]) -> [u32; 16] {
    std::array::from_fn(|i| u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]))
}

/// Message schedule `W[0..64]` (FIPS 180-4 §6.2.2 step 1).
pub fn message_schedule(m: &[u32; 16]) -> [u32; 64] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(m);
    for t in 16..64 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
    w
}

/// One compression round on working variables `[a, b, c, d, e, f, g, h]`.
#[inline(always)]
pub fn round(s: &State, k: u32, w: u32) -> State {
    let [a, b, c, d, e, f, g, h] = *s;
    let t1 = h
        .wrapping_add(big_sigma1(e))
        .wrapping_add(ch(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
    [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g]
}

/// Davies–Meyer feed-forward: word-wise `cv + s`.
#[inline(always)]
pub fn feed_forward(cv: &State, s: &State) -> State {
    std::array::from_fn(|i| cv[i].wrapping_add(s[i]))
}

/// Compression function with `rounds` rounds (0..=64) and the feed-forward.
/// `rounds == 64` is standard SHA-256.
pub fn compress_words(cv: &State, m: &[u32; 16], rounds: usize) -> State {
    assert!(rounds <= ROUNDS, "SHA-256 has at most {ROUNDS} rounds, got {rounds}");
    let w = message_schedule(m);
    let mut s = *cv;
    for t in 0..rounds {
        s = round(&s, K[t], w[t]);
    }
    feed_forward(cv, &s)
}

/// Standard 64-round compression of one 64-byte block.
pub fn compress(cv: &State, block: &[u8; 64]) -> State {
    compress_words(cv, &block_words(block), ROUNDS)
}

/// Everything observable inside one compression call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub rounds: usize,
    /// Full message schedule; entries at index >= `rounds` are computed but unused.
    pub schedule: [u32; 64],
    /// `states[0]` is the input chaining value; `states[t + 1]` is the state after round `t`.
    pub states: Vec<State>,
    /// Output after the feed-forward.
    pub output: State,
}

/// Compression with per-round state capture.
pub fn compress_traced(cv: &State, m: &[u32; 16], rounds: usize) -> Trace {
    assert!(rounds <= ROUNDS, "SHA-256 has at most {ROUNDS} rounds, got {rounds}");
    let schedule = message_schedule(m);
    let mut states = Vec::with_capacity(rounds + 1);
    let mut s = *cv;
    states.push(s);
    for t in 0..rounds {
        s = round(&s, K[t], schedule[t]);
        states.push(s);
    }
    Trace { rounds, schedule, states, output: feed_forward(cv, &s) }
}

/// Serialise a state as the 32-byte big-endian digest.
pub fn digest_bytes(s: &State) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(s) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Streaming SHA-256 with optional round reduction and tracing.
#[derive(Clone, Debug)]
pub struct Sha256 {
    state: State,
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
    rounds: usize,
    traces: Option<Vec<Trace>>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self::with_rounds(ROUNDS)
    }

    /// Reduced-round variant: every compression call uses `rounds` rounds.
    pub fn with_rounds(rounds: usize) -> Self {
        assert!(rounds <= ROUNDS, "SHA-256 has at most {ROUNDS} rounds, got {rounds}");
        Self { state: IV, buffer: [0; 64], buffered: 0, length: 0, rounds, traces: None }
    }

    /// Record a [`Trace`] for every compressed block.
    pub fn traced(mut self) -> Self {
        self.traces = Some(Vec::new());
        self
    }

    fn process(&mut self, block: &[u8; 64]) {
        let m = block_words(block);
        match &mut self.traces {
            Some(traces) => {
                let trace = compress_traced(&self.state, &m, self.rounds);
                self.state = trace.output;
                traces.push(trace);
            }
            None => self.state = compress_words(&self.state, &m, self.rounds),
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buffer;
            self.process(&block);
            self.buffered = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            self.process(block.try_into().expect("64-byte chunk"));
        }
        let rest = blocks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Padding (FIPS 180-4 §5.1.1): `0x80`, zeros, 64-bit big-endian bit length.
    fn finish(mut self) -> (State, Vec<Trace>) {
        let bit_len = self.length.wrapping_mul(8);
        let mut tail = [0u8; 128];
        tail[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
        tail[self.buffered] = 0x80;
        let total = if self.buffered < 56 { 64 } else { 128 };
        tail[total - 8..total].copy_from_slice(&bit_len.to_be_bytes());
        for block in tail[..total].chunks_exact(64) {
            self.process(block.try_into().expect("64-byte chunk"));
        }
        (self.state, self.traces.unwrap_or_default())
    }

    pub fn finalize(self) -> [u8; 32] {
        digest_bytes(&self.finish().0)
    }

    /// Digest plus one trace per compressed block (empty unless [`Sha256::traced`]).
    pub fn finalize_traced(self) -> ([u8; 32], Vec<Trace>) {
        let (state, traces) = self.finish();
        (digest_bytes(&state), traces)
    }
}

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // FIPS 180-4 / NIST CAVP example vectors.
    #[test]
    fn nist_vectors() {
        let cases: [(&[u8], &str); 4] = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (msg, want) in cases {
            assert_eq!(hex(&sha256(msg)), want, "message {:?}", String::from_utf8_lossy(msg));
        }
    }

    #[test]
    fn million_a() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(hex(&h.finalize()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    // FIPS 180-2 Appendix B.1 intermediate values for "abc".
    #[test]
    fn abc_round_states() {
        let (_, traces) = {
            let mut h = Sha256::new().traced();
            h.update(b"abc");
            h.finalize_traced()
        };
        assert_eq!(traces.len(), 1);
        let t = &traces[0];
        assert_eq!(t.schedule[0], 0x61626380);
        assert_eq!(t.schedule[15], 0x00000018);
        assert_eq!(t.schedule[16], 0x61626380);
        assert_eq!(
            t.states[1],
            [0x5d6aebcd, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xfa2a4622, 0x510e527f, 0x9b05688c, 0x1f83d9ab]
        );
        assert_eq!(
            t.states[64],
            [0x506e3058, 0xd39a2165, 0x04d24d6c, 0xb85e2ce9, 0x5ef50f24, 0xfb121210, 0x948d25b6, 0x961f4894]
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 + 7) as u8).collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 127, 128, 500, 1000] {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), sha256(&data), "split {split}");
        }
    }

    #[test]
    fn traced_and_untraced_agree_for_every_round_count() {
        let m: [u32; 16] = std::array::from_fn(|i| (i as u32).wrapping_mul(0x9e3779b9));
        for r in 0..=ROUNDS {
            let t = compress_traced(&IV, &m, r);
            assert_eq!(t.output, compress_words(&IV, &m, r));
            assert_eq!(t.states.len(), r + 1);
        }
    }

    #[test]
    fn zero_rounds_is_feed_forward_only() {
        let out = compress_words(&IV, &[0; 16], 0);
        assert_eq!(out, IV.map(|x| x.wrapping_add(x)));
    }
}
