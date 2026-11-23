//! Quantus QPoW miner: the exact node validity rule and a nonce search.
//!
//! Node rule (`qpow-math/src/lib.rs`): `target = U512::MAX / difficulty`,
//! valid iff `U512::from_big_endian(hash) < target` (strict). We compute the
//! target as a 64-byte big-endian array and compare lexicographically, which
//! is the same order on big-endian 512-bit integers.

use crate::qpow_hash;

/// `target = floor((2^512 - 1) / difficulty)` as 64 big-endian bytes.
pub fn target_be(difficulty: u64) -> [u8; 64] {
    assert!(difficulty > 0, "difficulty must be positive");
    let mut q = [0u8; 64];
    let mut rem: u128 = 0;
    for byte in q.iter_mut() {
        rem = (rem << 8) | 0xFF; // each byte of 2^512 - 1 is 0xFF
        *byte = (rem / difficulty as u128) as u8;
        rem %= difficulty as u128;
    }
    q
}

/// `hash < target` as big-endian 512-bit integers (strict; equality invalid).
#[inline]
pub fn is_valid(hash_be: &[u8; 64], target_be: &[u8; 64]) -> bool {
    for i in 0..64 {
        if hash_be[i] != target_be[i] {
            return hash_be[i] < target_be[i];
        }
    }
    false
}

/// `is_valid(qpow_hash(block_hash, nonce), target_be)` — the full predicate.
#[inline]
pub fn check_nonce(block_hash: &[u8; 32], nonce: &[u8; 64], target_be: &[u8; 64]) -> bool {
    is_valid(&qpow_hash(block_hash, nonce), target_be)
}

/// Search the low-64-bit nonce range `[start, start+count)` (high 448 bits
/// zero), returning the first valid `(counter, hash)`.
pub fn mine_range(
    block_hash: &[u8; 32],
    target_be: &[u8; 64],
    start: u64,
    count: u64,
) -> Option<(u64, [u8; 64])> {
    let mut nonce = [0u8; 64];
    let end = start.saturating_add(count);
    for ctr in start..end {
        nonce[56..64].copy_from_slice(&ctr.to_be_bytes());
        let h = qpow_hash(block_hash, &nonce);
        if is_valid(&h, target_be) {
            return Some((ctr, h));
        }
    }
    None
}

/// Build the 64-byte nonce used by `mine_range` for a counter value.
pub fn nonce_of(ctr: u64) -> [u8; 64] {
    let mut nonce = [0u8; 64];
    nonce[56..64].copy_from_slice(&ctr.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_div_exact_powers() {
        // difficulty 2^8: target = (2^512 - 1) >> 8, i.e. top byte 0x00, rest 0xFF.
        let t = target_be(256);
        assert_eq!(t[0], 0x00);
        assert!(t[1..].iter().all(|&b| b == 0xFF));
        // difficulty 1: target = 2^512 - 1 (all 0xFF).
        assert!(target_be(1).iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn is_valid_order() {
        let tgt = target_be(256); // top byte 0x00, rest 0xFF
        let h_ff = [0xFFu8; 64];
        assert!(!is_valid(&h_ff, &tgt)); // all-FF >= target
        let h_zero = [0u8; 64];
        assert!(is_valid(&h_zero, &tgt)); // 0 < target
        let mut h_below = [0xFFu8; 64];
        h_below[0] = 0x00;
        h_below[1] = 0x00; // strictly below [0x00, 0xFF, 0xFF, ...]
        assert!(is_valid(&h_below, &tgt));
        assert!(!is_valid(&tgt, &tgt)); // equality invalid (strict)
    }

    #[test]
    fn mine_finds_and_verifies_low_difficulty() {
        // difficulty 2^16: ~65k hashes expected. Must find one and it must verify.
        let bh = [0u8; 32];
        let tgt = target_be(1 << 16);
        let found = mine_range(&bh, &tgt, 0, 1 << 22).expect("should find at diff 2^16 within 4M");
        let (ctr, h) = found;
        // Re-derive and re-check independently.
        assert_eq!(h, qpow_hash(&bh, &nonce_of(ctr)));
        assert!(is_valid(&h, &tgt));
    }
}
