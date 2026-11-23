//! Goldilocks field, p = 2^64 - 2^32 + 1.
//!
//! Reference implementation: correct, not fast. Multiplication reduces a full
//! 128-bit product with `% P`, which is obviously correct; a faster
//! special-form reduction can replace it if throughput ever matters.
//! `ponytail: u128 mod, swap for the Plonky3 reduction if mul is the bottleneck`.
//!
//! All public functions take and return canonical values in `[0, P)`.

pub const P: u64 = 0xFFFF_FFFF_0000_0001;

#[inline]
fn red(x: u128) -> u64 {
    (x % P as u128) as u64
}

#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    red(a as u128 + b as u128)
}

#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    // b < P, so (P - b) > 0; a < P; sum < 2P.
    red(a as u128 + (P as u128 - b as u128))
}

#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    red(a as u128 * b as u128)
}

#[inline]
pub fn double(a: u64) -> u64 {
    add(a, a)
}

/// x^7 = x^2 * x * x^4, matching qp-poseidon's `exp7`.
#[inline]
pub fn exp7(x: u64) -> u64 {
    let x2 = mul(x, x);
    let x3 = mul(x2, x);
    let x4 = mul(x2, x2);
    mul(x3, x4)
}

/// Reduce a possibly-noncanonical u64 (< 2^64) into `[0, P)`.
/// 2^64 ≡ 2^32 - 1 (mod P), so a single value < 2^64 needs at most one fold.
#[inline]
pub fn canonicalize(a: u64) -> u64 {
    red(a as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_value() {
        // p = 2^64 - 2^32 + 1
        assert_eq!(P as u128, (1u128 << 64) - (1u128 << 32) + 1);
    }

    #[test]
    fn field_identities() {
        assert_eq!(add(P - 1, 1), 0);
        assert_eq!(sub(0, 1), P - 1);
        assert_eq!(mul(P - 1, P - 1), 1); // (-1)^2 = 1
        assert_eq!(mul(0, 12345), 0);
        assert_eq!(add(0, 0), 0);
        // 2^64 mod P = 2^32 - 1
        assert_eq!(red(1u128 << 64), 0xFFFF_FFFF);
    }

    #[test]
    fn exp7_known_answers() {
        // qp-poseidon test vectors.
        assert_eq!(exp7(2), 128);
        assert_eq!(exp7(5), 78125);
        assert_eq!(exp7(0xFFFF_FFFF), 0xFFFF_FFFF);
        assert_eq!(exp7(0), 0);
        assert_eq!(exp7(1), 1);
    }
}
