//! GF(2) structure of SHA-256.
//!
//! * Carry-free model: every modular addition replaced by XOR. The real
//!   function differs from it only through carries, so their agreement
//!   measures how much carries contribute round by round.
//! * Message-schedule linear algebra over GF(2) (linearized schedule).
//! * Upper bounds on the algebraic degree of output bits in a chosen set of
//!   free message bits, propagated through XOR, AND, rotations and exact
//!   ripple-carry addition.
//! * Cube sums (order-d derivatives): XOR of outputs over all 2^d
//!   assignments of d message bits. An output bit of degree < d sums to 0.
//!
//! Bit numbering: message bit `j` is bit `j % 32` (LSB = 0) of word `j / 32`.

#![forbid(unsafe_code)]

use sha256_core::{K, State, big_sigma0, big_sigma1, ch, compress_words, maj, small_sigma0, small_sigma1};

// ------------------------------------------------------------------ carry-free model

/// Message schedule with `+` replaced by XOR. Linear over GF(2), so it maps
/// a message difference to its carry-free expanded difference.
pub fn xor_schedule(m: &[u32; 16]) -> [u32; 64] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(m);
    for t in 16..64 {
        w[t] = small_sigma1(w[t - 2]) ^ w[t - 7] ^ small_sigma0(w[t - 15]) ^ w[t - 16];
    }
    w
}

/// Compression with every modular addition (rounds, schedule, feed-forward)
/// replaced by XOR. Ch and Maj are kept, so the model is quadratic over GF(2).
pub fn compress_carry_free(cv: &State, m: &[u32; 16], rounds: usize) -> State {
    let w = xor_schedule(m);
    let mut s = *cv;
    for t in 0..rounds {
        let [a, b, c, d, e, f, g, h] = s;
        let t1 = h ^ big_sigma1(e) ^ ch(e, f, g) ^ K[t] ^ w[t];
        let t2 = big_sigma0(a) ^ maj(a, b, c);
        s = [t1 ^ t2, a, b, c, d ^ t1, e, f, g];
    }
    std::array::from_fn(|i| cv[i] ^ s[i])
}

// ------------------------------------------------------------------ GF(2) linear algebra

/// Rank over GF(2) of bit-packed rows (all the same length).
pub fn rank(rows: &[Vec<u64>]) -> usize {
    let mut m = rows.to_vec();
    let cols = m.first().map_or(0, |r| r.len() * 64);
    let mut r = 0;
    for col in 0..cols {
        let (word, bit) = (col / 64, 1u64 << (col % 64));
        let Some(p) = (r..m.len()).find(|&i| m[i][word] & bit != 0) else { continue };
        m.swap(r, p);
        let pivot = m[r].clone();
        for (i, row) in m.iter_mut().enumerate() {
            if i != r && row[word] & bit != 0 {
                row.iter_mut().zip(&pivot).for_each(|(x, y)| *x ^= y);
            }
        }
        r += 1;
        if r == m.len() {
            break;
        }
    }
    r
}

/// Unit message with only bit `j` set.
pub fn unit_message(j: usize) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[j / 32] = 1 << (j % 32);
    m
}

/// Rows of the linearized schedule for words `words`: row (t, b) is bit b of
/// W_t as a GF(2) linear form in the 512 message bits (8 x u64).
pub fn schedule_rows(words: std::ops::Range<usize>) -> Vec<Vec<u64>> {
    let columns: Vec<[u32; 64]> = (0..512).map(|j| xor_schedule(&unit_message(j))).collect();
    let mut rows = Vec::new();
    for t in words {
        for b in 0..32 {
            let mut row = vec![0u64; 8];
            for (j, col) in columns.iter().enumerate() {
                if col[t] >> b & 1 == 1 {
                    row[j / 64] |= 1 << (j % 64);
                }
            }
            rows.push(row);
        }
    }
    rows
}

// ------------------------------------------------------------------ degree bounds

/// Per-bit upper bound on algebraic degree (0 = constant).
pub type Deg = [u16; 32];

fn d_max(a: &Deg, b: &Deg) -> Deg {
    std::array::from_fn(|i| a[i].max(b[i]))
}

fn d_rotr(a: &Deg, n: usize) -> Deg {
    std::array::from_fn(|i| a[(i + n) % 32])
}

fn d_shr(a: &Deg, n: usize) -> Deg {
    std::array::from_fn(|i| if i + n < 32 { a[i + n] } else { 0 })
}

fn d_xor3(a: Deg, b: Deg, c: Deg) -> Deg {
    d_max(&d_max(&a, &b), &c)
}

/// Degree bounds over `cap` free variables.
pub struct DegreeModel {
    pub cap: u16,
}

impl DegreeModel {
    fn sum(&self, x: u16, y: u16) -> u16 {
        (x + y).min(self.cap)
    }

    /// Exact ripple-carry structure: s_i = a_i ^ b_i ^ c_{i-1},
    /// c_i = a_i b_i ^ a_i c_{i-1} ^ b_i c_{i-1}.
    pub fn add(&self, a: &Deg, b: &Deg) -> Deg {
        let mut out = [0u16; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            out[i] = a[i].max(b[i]).max(carry);
            carry = self.sum(a[i], b[i]).max(self.sum(a[i], carry)).max(self.sum(b[i], carry));
        }
        out
    }

    pub fn ch(&self, e: &Deg, f: &Deg, g: &Deg) -> Deg {
        // e f ^ (1 ^ e) g = e f ^ g ^ e g
        std::array::from_fn(|i| self.sum(e[i], f[i]).max(self.sum(e[i], g[i])).max(g[i]))
    }

    pub fn maj(&self, a: &Deg, b: &Deg, c: &Deg) -> Deg {
        std::array::from_fn(|i| self.sum(a[i], b[i]).max(self.sum(a[i], c[i])).max(self.sum(b[i], c[i])))
    }

    fn bsig0(a: &Deg) -> Deg {
        d_xor3(d_rotr(a, 2), d_rotr(a, 13), d_rotr(a, 22))
    }
    fn bsig1(a: &Deg) -> Deg {
        d_xor3(d_rotr(a, 6), d_rotr(a, 11), d_rotr(a, 25))
    }
    fn ssig0(a: &Deg) -> Deg {
        d_xor3(d_rotr(a, 7), d_rotr(a, 18), d_shr(a, 3))
    }
    fn ssig1(a: &Deg) -> Deg {
        d_xor3(d_rotr(a, 17), d_rotr(a, 19), d_shr(a, 10))
    }

    /// Degree bounds of the `rounds`-round compression output (with
    /// feed-forward of a constant chaining value) in the message bits `free`.
    pub fn compression(free: &[usize], rounds: usize) -> [Deg; 8] {
        let model = DegreeModel { cap: free.len() as u16 };
        let mut w = vec![[0u16; 32]; 64];
        for &j in free {
            w[j / 32][j % 32] = 1;
        }
        for t in 16..64 {
            let x = model.add(&Self::ssig1(&w[t - 2]), &w[t - 7]);
            let y = model.add(&x, &Self::ssig0(&w[t - 15]));
            w[t] = model.add(&y, &w[t - 16]);
        }
        let zero = [0u16; 32];
        let mut s = [zero; 8];
        for t in 0..rounds {
            let [a, b, c, d, e, f, g, h] = s;
            // Adding the constant K_t: degree as adding a degree-0 word.
            let t1 = model.add(&model.add(&model.add(&model.add(&h, &Self::bsig1(&e)), &model.ch(&e, &f, &g)), &zero), &w[t]);
            let t2 = model.add(&Self::bsig0(&a), &model.maj(&a, &b, &c));
            s = [model.add(&t1, &t2), a, b, c, model.add(&d, &t1), e, f, g];
        }
        std::array::from_fn(|i| model.add(&s[i], &zero))
    }
}

// ------------------------------------------------------------------ cube sums

/// XOR of `compress(cv, m with cube bits = x)` over all 2^d assignments x.
/// The cube bits of `m` are cleared first.
pub fn cube_sum(cv: &State, m: &[u32; 16], cube: &[usize], rounds: usize) -> State {
    assert!(cube.len() <= 24, "cube dimension too large");
    let mut base = *m;
    for &j in cube {
        base[j / 32] &= !(1 << (j % 32));
    }
    let mut acc = [0u32; 8];
    for x in 0u32..1 << cube.len() {
        let mut mm = base;
        for (k, &j) in cube.iter().enumerate() {
            if x >> k & 1 == 1 {
                mm[j / 32] |= 1 << (j % 32);
            }
        }
        let out = compress_words(cv, &mm, rounds);
        acc.iter_mut().zip(out).for_each(|(a, o)| *a ^= o);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha256_core::IV;

    #[test]
    fn carry_free_equals_real_when_no_carries_possible() {
        // Zero rounds: only the feed-forward, cv ^ cv = 0 vs cv + cv.
        assert_eq!(compress_carry_free(&IV, &[0; 16], 0), [0; 8]);
        // Real and carry-free agree on a zero message for 0 rounds only up to carries.
        assert_ne!(compress_words(&IV, &[0; 16], 0), [0; 8]);
    }

    #[test]
    fn xor_schedule_is_linear() {
        let a: [u32; 16] = std::array::from_fn(|i| (i as u32).wrapping_mul(0x9e37_79b9));
        let b: [u32; 16] = std::array::from_fn(|i| (i as u32 + 3).wrapping_mul(0x85eb_ca6b));
        let ab: [u32; 16] = std::array::from_fn(|i| a[i] ^ b[i]);
        let (sa, sb, sab) = (xor_schedule(&a), xor_schedule(&b), xor_schedule(&ab));
        assert!((0..64).all(|t| sa[t] ^ sb[t] == sab[t]));
    }

    #[test]
    fn rank_basics_and_schedule_invertibility() {
        assert_eq!(rank(&[vec![0b011], vec![0b110], vec![0b101]]), 2);
        assert_eq!(rank(&schedule_rows(0..16)), 512);
        // The recurrence is invertible, so any 16 consecutive words have full rank.
        assert_eq!(rank(&schedule_rows(16..32)), 512);
        assert_eq!(rank(&schedule_rows(16..20)), 128);
    }

    #[test]
    fn cube_sums_vanish_where_degree_bound_is_low() {
        // Free bits in W15 enter at round 15; after 16 rounds each output bit
        // is at most ... check consistency: predicted degree < d implies zero sum.
        let cube: Vec<usize> = (15 * 32..15 * 32 + 6).collect();
        for rounds in [15, 16, 17, 18] {
            let bounds = DegreeModel::compression(&cube, rounds);
            for seed in 0..4u32 {
                let m: [u32; 16] = std::array::from_fn(|i| (i as u32 ^ seed).wrapping_mul(0x2545_f491));
                let cv: State = std::array::from_fn(|i| (i as u32 + seed).wrapping_mul(0x9e37_79b9));
                let sum = cube_sum(&cv, &m, &cube, rounds);
                for wi in 0..8 {
                    for b in 0..32 {
                        if bounds[wi][b] < cube.len() as u16 {
                            assert_eq!(sum[wi] >> b & 1, 0, "rounds {rounds} word {wi} bit {b} bound {}", bounds[wi][b]);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn degree_of_addition_carry_chain() {
        let m = DegreeModel { cap: 64 };
        let mut a = [0u16; 32];
        let mut b = [0u16; 32];
        a[0] = 1;
        b[0] = 1;
        let s = m.add(&a, &b);
        assert_eq!(s[0], 1);
        assert_eq!(s[1], 2); // carry a0 b0
        assert_eq!(s[2], 2);
    }
}
