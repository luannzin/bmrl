//! Quantus QPoW reference and output-bias attack harness.
//!
//! The live Quantus mainnet rule (pinned from `Quantus-Network/chain`,
//! `qpow-math/src/lib.rs`): a nonce is valid when
//! `U512::from_big_endian(Poseidon2_sponge(block_hash || nonce)) < U512::MAX / difficulty`.
//! The hash is `hash_squeeze_twice`: absorb the 96-byte input, squeeze 4
//! Goldilocks felts (32 bytes), permute once more, squeeze 4 more (32 bytes),
//! for a 512-bit output.
//!
//! The permutation is validated bit-for-bit against qp-poseidon's known-answer
//! vectors (see `poseidon2` and the sponge tests). `permute_rounds` exposes a
//! reduced-round knob so the attack harness can run a positive control.

#![forbid(unsafe_code)]

pub mod attack;
pub mod field;
pub mod miner;
pub mod poseidon2;

use field::canonicalize;
use poseidon2::{permute_rounds, HALF_EXTERNAL_ROUNDS, INTERNAL_ROUNDS, RATE, WIDTH};

/// Round schedule for the Poseidon2 permutation: (initial external, internal,
/// terminal external). Full Quantus is `FULL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rounds {
    pub ext_init: usize,
    pub n_int: usize,
    pub ext_term: usize,
}

impl Rounds {
    pub const FULL: Rounds = Rounds {
        ext_init: HALF_EXTERNAL_ROUNDS,
        n_int: INTERNAL_ROUNDS,
        ext_term: HALF_EXTERNAL_ROUNDS,
    };
}

/// Map input bytes to Goldilocks felts exactly as qp-poseidon's
/// `bytes_to_felts_iter`: 4 little-endian bytes per full chunk, then always one
/// terminator felt `u32::from_le_bytes([rem.., 1, 0..])`.
fn bytes_to_felts(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::with_capacity(bytes.len() / 4 + 1);
    let mut pos = 0;
    while pos + 4 <= bytes.len() {
        out.push(u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as u64);
        pos += 4;
    }
    let rem = &bytes[pos..];
    let mut last = [0u8; 4];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] = 1;
    out.push(u32::from_le_bytes(last) as u64);
    out
}

/// qp-poseidon sponge: additive absorb into the rate lanes, permute on a full
/// block, finalize with a single 1 then zeros to the block boundary.
struct Sponge {
    state: [u64; WIDTH],
    buf: [u64; RATE],
    buf_len: usize,
    rounds: Rounds,
}

impl Sponge {
    fn new(rounds: Rounds) -> Self {
        Self { state: [0; WIDTH], buf: [0; RATE], buf_len: 0, rounds }
    }

    fn permute(&mut self) {
        permute_rounds(&mut self.state, self.rounds.ext_init, self.rounds.n_int, self.rounds.ext_term);
    }

    fn absorb_block(&mut self) {
        for i in 0..RATE {
            self.state[i] = field::add(self.state[i], self.buf[i]);
        }
        self.permute();
        self.buf = [0; RATE];
        self.buf_len = 0;
    }

    fn push(&mut self, x: u64) {
        self.buf[self.buf_len] = x;
        self.buf_len += 1;
        if self.buf_len == RATE {
            self.absorb_block();
        }
    }

    fn append_bytes(&mut self, bytes: &[u8]) {
        for f in bytes_to_felts(bytes) {
            self.push(f);
        }
    }

    fn finalize(&mut self) {
        self.push(1);
        while self.buf_len != 0 {
            self.push(0);
        }
    }

    fn digest_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&canonicalize(self.state[i]).to_le_bytes());
        }
        out
    }
}

/// qp-poseidon `hash_bytes`: 256-bit digest of `bytes`.
pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut s = Sponge::new(Rounds::FULL);
    s.append_bytes(bytes);
    s.finalize();
    s.digest_bytes()
}

/// qp-poseidon `hash_squeeze_twice`: 512-bit digest (two squeezes) of `bytes`,
/// under a given round schedule. `Rounds::FULL` is the live Quantus hash.
pub fn hash_squeeze_twice_rounds(bytes: &[u8], rounds: Rounds) -> [u8; 64] {
    let mut s = Sponge::new(rounds);
    s.append_bytes(bytes);
    s.finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&s.digest_bytes());
    s.permute();
    out[32..].copy_from_slice(&s.digest_bytes());
    out
}

/// The Quantus QPoW 512-bit hash of `block_hash (32) || nonce (64)`.
pub fn qpow_hash_rounds(block_hash: &[u8; 32], nonce: &[u8; 64], rounds: Rounds) -> [u8; 64] {
    let mut input = [0u8; 96];
    input[..32].copy_from_slice(block_hash);
    input[32..].copy_from_slice(nonce);
    hash_squeeze_twice_rounds(&input, rounds)
}

/// Live Quantus QPoW hash (full rounds).
pub fn qpow_hash(block_hash: &[u8; 32], nonce: &[u8; 64]) -> [u8; 64] {
    qpow_hash_rounds(block_hash, nonce, Rounds::FULL)
}

/// Top 64 bits of the big-endian 512-bit output — the "smallness" the target
/// test compares. A valid nonce needs this (and the rest) below `MAX/difficulty`.
#[inline]
pub fn top64_be(hash: &[u8; 64]) -> u64 {
    u64::from_be_bytes(hash[..8].try_into().unwrap())
}

/// "Luck" of an output in [0, 1): its value divided by 2^512, approximated by
/// the top 64 bits. Uniform over nonces iff the hash has no exploitable bias.
#[inline]
pub fn luck(hash: &[u8; 64]) -> f64 {
    top64_be(hash) as f64 / 2.0f64.powi(64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn hash_bytes_known_answers() {
        // qp-poseidon test_known_value_hashes.
        assert_eq!(hex(&hash_bytes(&[])), "4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86");
        assert_eq!(hex(&hash_bytes(&[0])), "8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad");
        assert_eq!(hex(&hash_bytes(&[0u8; 8])), "eacd9e48d2e968131e48c8e69f2a211cc06c7778db6c5467348b45418fc7f585");
        assert_eq!(hex(&hash_bytes(&[0, 0, 0, 1])), "6ffff0c97262139567c426e916c1fd70c924010153c366bb2a8957ea89902942");
        assert_eq!(hex(&hash_bytes(&[1, 2, 3, 4, 5, 6, 7, 8])), "131020b2e74819343f8568258ae2e9717e9b2253d57baabab78a518bc7499a8b");
        assert_eq!(hex(&hash_bytes(&[0xFF; 32])), "41260a4322e97dc3dda2b5f70b5ffb1b43071ad5510e101f34209721042c0987");
        assert_eq!(hex(&hash_bytes(b"hello world")), "fd1f5d7d4701c25bbdd5dd6e3be6abb474fffbaa402f814dce95f8283abbf3e7");
        let seq32: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(hex(&hash_bytes(&seq32)), "36884f9093be80632397f5736dce2fece627a4182daf3cdbf8bf12c8e3e02668");
        let seq64: [u8; 64] = std::array::from_fn(|i| i as u8);
        assert_eq!(hex(&hash_bytes(&seq64)), "dd0d06fbe4e7575d0eeac53706482cbbe592e269a35bcd5591a495814371724e");
    }

    #[test]
    fn squeeze_twice_first_half_is_hash_bytes() {
        // qp-poseidon invariant: out[0..32] == hash_bytes(input).
        let input = b"test 512-bit hash";
        let full = hash_squeeze_twice_rounds(input, Rounds::FULL);
        assert_eq!(full[..32], hash_bytes(input));
        // Deterministic and input-sensitive.
        assert_eq!(full, hash_squeeze_twice_rounds(input, Rounds::FULL));
        assert_ne!(full, hash_squeeze_twice_rounds(b"test 512-bit hasi", Rounds::FULL));
    }

    #[test]
    fn qpow_hash_shape() {
        let bh = [7u8; 32];
        let n = [9u8; 64];
        let h = qpow_hash(&bh, &n);
        // First half equals the 256-bit hash of the 96-byte input.
        let mut input = [0u8; 96];
        input[..32].copy_from_slice(&bh);
        input[32..].copy_from_slice(&n);
        assert_eq!(h[..32], hash_bytes(&input));
    }
}
