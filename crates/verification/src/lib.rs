//! Independent verification.
//!
//! [`independent`] is a second SHA-256 written separately from `sha256-core`:
//! constants are *derived* from their FIPS 180-4 definition (fractional parts
//! of square/cube roots of primes) with integer arithmetic, registers rotate by
//! index instead of being shifted, and the schedule is a 16-word ring.
//! The suites compare it, `sha256-core` and the third-party `sha2` crate.

#![forbid(unsafe_code)]

use bitcoin_header::{
    BlockHeader, HeaderMidstate, MAINNET_POW_LIMIT_BITS, Target, check_proof_of_work, display_hex, fixtures, merkle_root,
    parse_display_hex,
};
use serde::Serialize;
use sha2::Digest;
use statistical_engine::SplitMix64;

pub mod independent {
    fn primes(n: usize) -> Vec<u128> {
        let mut out = Vec::with_capacity(n);
        let mut c = 2u128;
        while out.len() < n {
            if (2..c).take_while(|d| d * d <= c).all(|d| c % d != 0) {
                out.push(c);
            }
            c += 1;
        }
        out
    }

    /// floor(x^(1/k)) for k in {2, 3} by binary search.
    fn iroot(x: u128, k: u32) -> u128 {
        let (mut lo, mut hi) = (0u128, 1u128 << (128 / k + 1));
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            match mid.checked_pow(k) {
                Some(v) if v <= x => lo = mid,
                _ => hi = mid - 1,
            }
        }
        lo
    }

    /// `K[i]`: first 32 fractional bits of cbrt(prime i); `IV[i]`: of sqrt(prime i).
    pub fn derive_constants() -> ([u32; 64], [u32; 8]) {
        let p = primes(64);
        let k = std::array::from_fn(|i| iroot(p[i] << 96, 3) as u32);
        let iv = std::array::from_fn(|i| iroot(p[i] << 64, 2) as u32);
        (k, iv)
    }

    fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }

    #[derive(Clone, Debug)]
    pub struct Sha256 {
        k: [u32; 64],
        iv: [u32; 8],
    }

    impl Default for Sha256 {
        fn default() -> Self {
            let (k, iv) = derive_constants();
            Self { k, iv }
        }
    }

    impl Sha256 {
        pub fn iv(&self) -> [u32; 8] {
            self.iv
        }

        /// Compression with `rounds` rounds and feed-forward.
        pub fn compress(&self, cv: &[u32; 8], m: &[u32; 16], rounds: usize) -> [u32; 8] {
            assert!(rounds <= 64);
            let mut v = *cv;
            let mut ring = *m;
            for t in 0..rounds {
                let w = if t < 16 {
                    ring[t]
                } else {
                    let x2 = ring[(t + 14) & 15];
                    let x15 = ring[(t + 1) & 15];
                    let s1 = rotr(x2, 17) ^ rotr(x2, 19) ^ (x2 >> 10);
                    let s0 = rotr(x15, 7) ^ rotr(x15, 18) ^ (x15 >> 3);
                    let w = s1.wrapping_add(ring[(t + 9) & 15]).wrapping_add(s0).wrapping_add(ring[t & 15]);
                    ring[t & 15] = w;
                    w
                };
                // Register j (a=0..h=7) lives in slot (j - t) mod 8.
                let r = |j: usize| (j + 8 - (t & 7)) & 7;
                let (a, b, c, e, f, g, h) = (v[r(0)], v[r(1)], v[r(2)], v[r(4)], v[r(5)], v[r(6)], v[r(7)]);
                let t1 = h
                    .wrapping_add(rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25))
                    .wrapping_add((e & f) | (!e & g))
                    .wrapping_add(self.k[t])
                    .wrapping_add(w);
                let t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)).wrapping_add((a & b) | (c & (a | b)));
                v[r(3)] = v[r(3)].wrapping_add(t1);
                v[r(7)] = t1.wrapping_add(t2);
            }
            let r = |j: usize| (j + 8 - (rounds & 7)) & 7;
            std::array::from_fn(|j| cv[j].wrapping_add(v[r(j)]))
        }

        /// Whole-message hash with `rounds`-round compressions; pads by
        /// building the full padded message first.
        pub fn digest(&self, data: &[u8], rounds: usize) -> [u8; 32] {
            let mut msg = data.to_vec();
            msg.push(0x80);
            while msg.len() % 64 != 56 {
                msg.push(0);
            }
            msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
            let mut h = self.iv;
            for block in msg.chunks_exact(64) {
                let m = std::array::from_fn(|i| u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes")));
                h = self.compress(&h, &m, rounds);
            }
            let mut out = [0u8; 32];
            for (i, w) in h.iter().enumerate() {
                out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
            }
            out
        }

        pub fn sha256d(&self, data: &[u8], rounds: usize) -> [u8; 32] {
            self.digest(&self.digest(data, rounds), rounds)
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn check(&mut self, name: impl Into<String>, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check { name: name.into(), passed, detail: detail.into() });
    }

    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
}

fn hex(b: &[u8]) -> String {
    bitcoin_header::hex_encode(b)
}

fn sha2_256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// SHA-256d by the third-party `sha2` crate, for cross-checks outside this crate.
pub fn third_party_sha256d(data: &[u8]) -> [u8; 32] {
    sha2_256(&sha2_256(data))
}

/// SHA-256 / SHA-256d correctness across three implementations.
pub fn sha256_suite(random_cases: u64, seed: u64) -> Report {
    let mut r = Report::default();
    let ind = independent::Sha256::default();

    let (k, iv) = independent::derive_constants();
    r.check("constants.K derived from cube roots", k == sha256_core::K, "64 round constants");
    r.check("constants.IV derived from square roots", iv == sha256_core::IV, "8 initial words");

    let million_a = vec![b'a'; 1_000_000];
    let nist: [(&str, &[u8], &str); 5] = [
        ("empty", b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "448-bit",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            "896-bit",
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
        ("million-a", &million_a, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ];
    for (name, msg, want) in nist {
        let got = [hex(&sha256_core::sha256(msg)), hex(&ind.digest(msg, 64)), hex(&sha2_256(msg))];
        r.check(format!("sha256.nist.{name}"), got.iter().all(|g| g == want), format!("expected {want}"));
    }

    let d_vectors: [(&str, &[u8], &str); 2] = [
        ("empty", b"", "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"),
        ("hello", b"hello", "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"),
    ];
    for (name, msg, want) in d_vectors {
        let got = [hex(&sha256d::sha256d(msg)), hex(&ind.sha256d(msg, 64)), hex(&sha2_256(&sha2_256(msg)))];
        r.check(format!("sha256d.vector.{name}"), got.iter().all(|g| g == want), format!("expected {want}"));
    }

    let mut mismatches = 0u64;
    for i in 0..random_cases {
        let mut rng = SplitMix64::stream(seed, i);
        let len = (rng.next_u32() % 2048) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.next_u32() as u8).collect();
        let a = sha256_core::sha256(&data);
        if a != ind.digest(&data, 64) || a != sha2_256(&data) || sha256d::sha256d(&data) != sha2_256(&a) {
            mismatches += 1;
        }
    }
    r.check(
        "sha256.random-cross-check",
        mismatches == 0,
        format!("{random_cases} random messages (0..2048 bytes, seed {seed}) vs sha2 crate and independent impl; {mismatches} mismatches"),
    );

    let mut rr_mismatch = 0;
    for i in 0..64u64 {
        let mut rng = SplitMix64::stream(seed ^ 0x5244, i);
        let (cv, m): ([u32; 8], [u32; 16]) = (rng.words(), rng.words());
        for rounds in 0..=64 {
            if sha256_core::compress_words(&cv, &m, rounds) != ind.compress(&cv, &m, rounds) {
                rr_mismatch += 1;
            }
        }
    }
    r.check(
        "sha256.reduced-round-cross-check",
        rr_mismatch == 0,
        format!("64 random (cv, block) pairs x rounds 0..=64; {rr_mismatch} mismatches"),
    );
    r
}

/// Bitcoin header engine correctness against real main-network blocks.
pub fn header_suite() -> Report {
    let mut r = Report::default();
    for k in fixtures::MAINNET {
        let name = format!("header.mainnet.{}", k.height);
        let h = match BlockHeader::from_hex(k.header_hex) {
            Ok(h) => h,
            Err(e) => {
                r.check(name, false, e.to_string());
                continue;
            }
        };
        let bytes = h.serialize();
        let paths = [
            display_hex(&h.hash()),
            display_hex(&HeaderMidstate::new(&bytes).hash(h.nonce)),
            display_hex(&sha2_256(&sha2_256(&bytes))),
        ];
        let fields_ok = (h.version, h.time, h.bits, h.nonce) == (k.version, k.time, k.bits, k.nonce);
        let pow = check_proof_of_work(&h.hash(), h.bits, MAINNET_POW_LIMIT_BITS);
        r.check(
            name,
            h.to_hex() == k.header_hex && fields_ok && paths.iter().all(|p| p == k.hash) && pow == Ok(true),
            format!("hash {} (core / midstate / sha2), pow {:?}", k.hash, pow),
        );
    }

    let txids: Result<Vec<_>, _> = fixtures::BLOCK_100000_TXIDS.iter().map(|t| parse_display_hex(t)).collect();
    let ok = txids.is_ok_and(|txids| {
        let merkle = merkle_root(&txids);
        let h = BlockHeader {
            version: 1,
            prev_blockhash: parse_display_hex(fixtures::BLOCK_100000_PREV).expect("fixture"),
            merkle_root: merkle,
            time: fixtures::BLOCK_100000_TIME,
            bits: fixtures::BLOCK_100000_BITS,
            nonce: fixtures::BLOCK_100000_NONCE,
        };
        display_hex(&merkle) == fixtures::BLOCK_100000_MERKLE
            && h.block_hash_hex() == fixtures::BLOCK_100000_HASH
            && check_proof_of_work(&h.hash(), h.bits, MAINNET_POW_LIMIT_BITS) == Ok(true)
    });
    r.check("header.mainnet.100000.from-txids", ok, "merkle root from 4 txids, header from fields, PoW valid");

    let compact_cases = [(0x1d00ffffu32, 0x1d00ffffu32), (0x1a44b9f2, 0x1a44b9f2), (0x207fffff, 0x207fffff), (0x04923456, 0x04123456)];
    let compact_ok = compact_cases.iter().all(|&(bits, back)| Target::from_compact(bits).target.to_compact() == back);
    r.check("target.compact-roundtrip", compact_ok, "SetCompact/GetCompact parity with Bitcoin Core semantics");
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suites_pass() {
        let s = sha256_suite(200, 1);
        assert!(s.passed(), "{:#?}", s.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>());
        let h = header_suite();
        assert!(h.passed(), "{:#?}", h.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>());
    }
}
