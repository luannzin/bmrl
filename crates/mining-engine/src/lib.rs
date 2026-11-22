//! Production mining layer: work units, the backend interface every hashing
//! engine implements, and Bitcoin Core regtest integration.
//!
//! Research code never feeds this crate directly. A nonce reported by any
//! backend is re-checked with the reference path ([`Work::verify`]: full
//! SHA-256d of the serialized header, no midstate) before it is used.

pub mod regtest;
pub mod rpc;

use bitcoin_header::{BlockHeader, HEADER_LEN, HeaderMidstate, Target};

/// One nonce-search job: a header (nonce field ignored) and a target.
#[derive(Clone, Debug)]
pub struct Work {
    pub header: BlockHeader,
    pub target: Target,
    pub midstate: HeaderMidstate,
}

impl Work {
    pub fn new(header: BlockHeader, target: Target) -> Self {
        Self { header, target, midstate: HeaderMidstate::new(&header.serialize()) }
    }

    pub fn header_bytes(&self) -> [u8; HEADER_LEN] {
        self.header.serialize()
    }

    /// The same job with BIP320 version bits 13..=28 XORed with `m`: a new
    /// midstate, an identical second block (overt AsicBoost).
    pub fn version_rolled(&self, m: u32) -> Work {
        let mut h = self.header;
        h.version ^= ((m << 13) & 0x1fff_e000) as i32;
        Work::new(h, self.target)
    }

    /// Reference check: SHA-256d over the full 80-byte header.
    pub fn verify(&self, nonce: u32) -> bool {
        let mut h = self.header;
        h.nonce = nonce;
        self.target.is_met_by(&h.hash())
    }
}

/// Outcome of scanning a nonce range.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Nonces meeting the target, ascending.
    pub found: Vec<u32>,
    /// Nonces actually evaluated (may be < range when stopped early).
    pub hashes: u64,
}

/// A hashing engine. `scan` evaluates nonces `start .. start + count`
/// (`start + count <= 2^32`) and returns every nonce meeting the target.
/// Once `max_found` hits are collected it may stop early; the returned set is
/// then a subset of the hits, not necessarily the smallest ones.
pub trait Backend: Send + Sync {
    fn name(&self) -> String;
    fn scan(&self, work: &Work, start: u32, count: u64, max_found: usize) -> anyhow::Result<Scan>;
}

/// Search the whole 32-bit nonce space for one valid nonce, in slices of
/// `slice` nonces so a hit is returned without scanning everything.
pub fn find_nonce(backend: &dyn Backend, work: &Work, slice: u64) -> anyhow::Result<(Option<u32>, u64)> {
    let mut hashes = 0;
    let mut start = 0u64;
    while start < 1 << 32 {
        let count = slice.min((1 << 32) - start);
        let scan = backend.scan(work, start as u32, count, 1)?;
        hashes += scan.hashes;
        if let Some(&nonce) = scan.found.first() {
            anyhow::ensure!(work.verify(nonce), "backend {} reported invalid nonce {nonce:#010x}", backend.name());
            return Ok((Some(nonce), hashes));
        }
        start += count;
    }
    Ok((None, hashes))
}

/// Several backends searching one range together: the range is split in
/// proportion to `weights` (e.g. measured hash rates) and the parts run
/// concurrently on their own threads.
pub struct Split {
    pub parts: Vec<(Box<dyn Backend>, f64)>,
}

impl Backend for Split {
    fn name(&self) -> String {
        self.parts.iter().map(|(b, _)| b.name()).collect::<Vec<_>>().join(" + ")
    }

    fn scan(&self, work: &Work, start: u32, count: u64, max_found: usize) -> anyhow::Result<Scan> {
        let total: f64 = self.parts.iter().map(|(_, w)| w).sum();
        let mut ranges = Vec::new();
        let mut s = start as u64;
        for (i, (_, w)) in self.parts.iter().enumerate() {
            let n = if i + 1 == self.parts.len() { start as u64 + count - s } else { (count as f64 * w / total) as u64 };
            ranges.push((s, n));
            s += n;
        }
        let results: Vec<anyhow::Result<Scan>> = std::thread::scope(|sc| {
            let handles: Vec<_> = self.parts.iter().zip(&ranges).map(|((b, _), &(s, n))| sc.spawn(move || b.scan(work, s as u32, n, max_found))).collect();
            handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(anyhow::anyhow!("backend thread panicked")))).collect()
        });
        let mut out = Scan::default();
        for r in results {
            let r = r?;
            out.found.extend(r.found);
            out.hashes += r.hashes;
        }
        out.found.sort_unstable();
        Ok(out)
    }
}

/// Every hit in a range, checked against the reference path.
pub fn scan_verified(backend: &dyn Backend, work: &Work, start: u32, count: u64) -> anyhow::Result<Scan> {
    let scan = backend.scan(work, start, count, usize::MAX)?;
    if let Some(bad) = scan.found.iter().find(|&&n| !work.verify(n)) {
        anyhow::bail!("backend {} reported invalid nonce {bad:#010x}", backend.name());
    }
    Ok(scan)
}

/// Simple deterministic test work: a header from fixed fields and a target
/// with `zero_bits` leading zero bits (success probability ~ 2^-zero_bits).
pub fn synthetic_work(seed: u32, zero_bits: u32) -> Work {
    let mut prev = [0u8; 32];
    let mut merkle = [0u8; 32];
    for i in 0..32 {
        prev[i] = (seed.wrapping_mul(2654435761).wrapping_add(i as u32 * 97) >> 7) as u8;
        merkle[i] = (seed.wrapping_mul(40503).wrapping_add(i as u32 * 131) >> 3) as u8;
    }
    let header = BlockHeader { version: 0x2000_0000, prev_blockhash: prev, merkle_root: merkle, time: 1_700_000_000 + seed, bits: 0x1d00ffff, nonce: 0 };
    Work::new(header, target_with_zero_bits(zero_bits))
}

/// Largest target with `zero_bits` leading zero bits.
pub fn target_with_zero_bits(zero_bits: u32) -> Target {
    assert!(zero_bits < 256);
    let mut t = [0xffu8; 32];
    for (i, byte) in t.iter_mut().enumerate() {
        let bit = i as u32 * 8;
        if bit + 8 <= zero_bits {
            *byte = 0;
        } else if bit < zero_bits {
            *byte = 0xff >> (zero_bits - bit);
        }
    }
    Target(t)
}

/// Naive single-thread baseline: serialize, then full SHA-256d per nonce.
pub struct ReferenceBackend;

impl Backend for ReferenceBackend {
    fn name(&self) -> String {
        "reference (full sha256d, 1 thread)".into()
    }

    fn scan(&self, work: &Work, start: u32, count: u64, max_found: usize) -> anyhow::Result<Scan> {
        anyhow::ensure!(start as u64 + count <= 1 << 32, "nonce range exceeds 2^32");
        let mut bytes = work.header_bytes();
        let mut scan = Scan::default();
        for i in 0..count {
            let nonce = start.wrapping_add(i as u32);
            bytes[76..80].copy_from_slice(&nonce.to_le_bytes());
            scan.hashes += 1;
            if work.target.is_met_by(&sha256_core::sha256(&sha256_core::sha256(&bytes))) {
                scan.found.push(nonce);
                if scan.found.len() >= max_found {
                    break;
                }
            }
        }
        Ok(scan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_bits() {
        assert_eq!(target_with_zero_bits(0).leading_zeros(), 0);
        assert_eq!(target_with_zero_bits(12).leading_zeros(), 12);
        assert_eq!(target_with_zero_bits(32).words()[1], u32::MAX);
        assert_eq!(target_with_zero_bits(36).words()[1], 0x0fff_ffff);
    }

    #[test]
    fn split_backend_covers_the_range_once() {
        let work = synthetic_work(2, 6);
        let split = Split { parts: vec![(Box::new(ReferenceBackend), 1.0), (Box::new(ReferenceBackend), 3.0)] };
        let whole = ReferenceBackend.scan(&work, 100, 10_007, usize::MAX).unwrap();
        assert_eq!(scan_verified(&split, &work, 100, 10_007).unwrap(), whole);
    }

    #[test]
    fn reference_backend_hits_are_valid() {
        let work = synthetic_work(1, 8);
        let scan = scan_verified(&ReferenceBackend, &work, 0, 4096).unwrap();
        assert_eq!(scan.hashes, 4096);
        // ~16 expected hits at 2^-8.
        assert!((4..=40).contains(&scan.found.len()), "{}", scan.found.len());
    }
}
