//! Goldilocks field, p = 2^64 - 2^32 + 1.
//!
//! Reference implementation: correct, not fast. Multiplication reduces a full
//! 128-bit product with `% P`, which is obviously correct; a faster
//! special-form reduction can replace it if throughput ever matters.
//! `ponytail: u128 mod, swap for the Plonky3 reduction if mul is the bottleneck`.
//!
//! All public functions take and return canonical values in `[0, P)`.

pub const P: u64 = 0xFFFF_FFFF_0000_0001;
/// 2^32 - 1 = 2^64 mod P.
pub const EPSILON: u64 = 0xFFFF_FFFF;

#[inline]
fn red(x: u128) -> u64 {
    (x % P as u128) as u64
}

/// Canonicalize a value in `[0, 2^64)` to `[0, P)`. Single subtraction is
/// enough because every value this crate produces is `< 2P`.
#[inline]
pub fn canonicalize(a: u64) -> u64 {
    if a >= P { a - P } else { a }
}

/// Reduce a 128-bit product mod P to a value in `[0, 2^64)` (possibly
/// non-canonical), using 2^64 ≡ 2^32 - 1 (mod P). The standard Plonky3
/// Goldilocks reduction. Validated against `mul_ref` and the Poseidon2 KATs.
#[inline]
pub fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & EPSILON;

    let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    if borrow {
        t0 = t0.wrapping_sub(EPSILON);
    }
    let t1 = x_hi_lo * EPSILON;
    let (res, carry) = t0.overflowing_add(t1);
    if carry { res.wrapping_add(EPSILON) } else { res }
}

/// Inputs may be non-canonical (`< 2^64`); result is reduced to `[0, 2^64)`.
#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    reduce128(a as u128 + b as u128)
}

/// Inputs may be non-canonical; result is canonical `[0, P)`.
#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    let a = canonicalize(a);
    let b = canonicalize(b);
    canonicalize(reduce128(a as u128 + (P as u128 - b as u128)))
}

/// Fast multiply. Inputs may be non-canonical (`< 2^64`); result is in
/// `[0, 2^64)` (reduced mod P, not necessarily canonical). Canonicalize before
/// comparing or emitting.
#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce128(a as u128 * b as u128)
}

/// Reference multiply via full `% P`, obviously correct; used to validate `mul`.
#[inline]
pub fn mul_ref(a: u64, b: u64) -> u64 {
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
        assert_eq!(canonicalize(add(P - 1, 1)), 0); // add may be non-canonical
        assert_eq!(sub(0, 1), P - 1); // sub returns canonical
        assert_eq!(canonicalize(mul(P - 1, P - 1)), 1); // (-1)^2 = 1
        assert_eq!(canonicalize(mul(0, 12345)), 0);
        assert_eq!(canonicalize(add(0, 0)), 0);
        // 2^64 mod P = 2^32 - 1
        assert_eq!(red(1u128 << 64), 0xFFFF_FFFF);
    }

    #[test]
    fn fast_mul_matches_reference() {
        // Deterministic LCG over a wide range of inputs, including non-canonical.
        let mut s: u64 = 0x1234_5678_9abc_def1;
        let mut next = || {
            s = s.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(0x1);
            s
        };
        for _ in 0..200_000 {
            let a = next();
            let b = next();
            assert_eq!(canonicalize(mul(a, b)), mul_ref(canonicalize(a), canonicalize(b)));
        }
        // Edge cases.
        for &a in &[0u64, 1, 2, P - 1, P, P + 1, EPSILON, u64::MAX, 1 << 32, 1 << 63] {
            for &b in &[0u64, 1, P - 1, P, u64::MAX, EPSILON] {
                assert_eq!(canonicalize(mul(a, b)), mul_ref(canonicalize(a), canonicalize(b)));
            }
        }
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
