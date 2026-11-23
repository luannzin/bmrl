//! Poseidon2 permutation over Goldilocks, width 12, as deployed by Quantus
//! (`Quantus-Network/qp-poseidon`). Constants are the literal arrays from that
//! crate (generated with seed 0x3141592653589793). Validated against the
//! repo's permutation known-answer vectors in the tests below.

use crate::field::{add, double, exp7, mul};

pub const WIDTH: usize = 12;
pub const RATE: usize = 8;
pub const CAPACITY: usize = WIDTH - RATE; // 4
pub const OUTPUT: usize = 4;
pub const INTERNAL_ROUNDS: usize = 22;
pub const EXTERNAL_ROUNDS: usize = 8;
pub const HALF_EXTERNAL_ROUNDS: usize = EXTERNAL_ROUNDS / 2; // 4

pub const INTERNAL_CONSTANTS: [u64; 22] = [
    0x97f7798a784ad863, 0xd1d2bf082f60d4f0, 0x69a377a79f9ad206, 0xa9d06906a3858e24,
    0x295275001eede5b5, 0x5874e441117bd746, 0x8a084bbba8ed86cc, 0x3defd7645cde6425,
    0x3998cfe6871cc137, 0x3e52ef8bca48314a, 0x964a209f85dc9ecc, 0x3fcc9ee82cc4577e,
    0x8e79b4a5d0096d6d, 0x8492362ad2392556, 0xee72f470262574d6, 0x1e0e18496da2444a,
    0x0f3a74bf215eaac6, 0x1b061b76a1c0ded3, 0x192c42d86803d7a6, 0xf6d49ff997ae0260,
    0x3ec372e7a0fa3786, 0x5538cdf4f23445d3,
];

pub const MATRIX_DIAG: [u64; 12] = [
    0xc3b6c08e23ba9300, 0xd84b5de94a324fb6, 0x0d0c371c5b35b84f, 0x7964f570e7188037,
    0x5daf18bbd996604b, 0x6743bc47b9595257, 0x5528b9362c59bb70, 0xac45e25b7127b68b,
    0xa2077d7dfbb606b5, 0xf3faac6faee378ae, 0x0c6388b51545e883, 0xd27dbb6944917b60,
];

pub const INITIAL_EXTERNAL_CONSTANTS: [[u64; 12]; 4] = [
    [0xc002e770975b1607, 0xbca51a8dfe14593a, 0x72938dfbe774f7f9, 0xe4f2fe29e03234ac, 0xd5e0ba2f541b6449, 0xec33b868f3cc46c1, 0x486dcb55419d475a, 0x6c1cb2a358cc24f1, 0xe3f30d509a1436bb, 0xd9a64f068dca7c29, 0xe59b3f57aabba1ae, 0x2a3dd4505b478fdc],
    [0xada1f8dc7676ed25, 0x2711aa8b5509d516, 0x4ae6acd0c9c92897, 0x56eb3d6b5256d67a, 0x1f7a9d55923bf51e, 0x3600427d397a7f68, 0xe5076df75b72c3d0, 0xfcd59aa12c6090ad, 0xcd895e8c68b57a9e, 0x41df7ef9d730ae3e, 0xee3e2b889abe977d, 0xd29bb7edbeb9c405],
    [0x7d5c08eef608e382, 0x89ae889caaf0802c, 0xb35a8e976d2af617, 0xdb14234eafaf5173, 0x78f04462d48b1c98, 0x265293b0e47ce88a, 0x999a649b69b9d32f, 0x64b0a186698e01d3, 0xee0b22d0dfae8bb8, 0x4fd53e50ca04a7ee, 0x5762bfe181f25047, 0xf51593e2beb5e3bd],
    [0x1e5e2b5760e32477, 0x622462a1f9aaaeed, 0xaa284b3ecdb222ae, 0x63c8e72f542bf3fc, 0x3ba588cacb43b5e0, 0x23eda6f3c99150dd, 0xaad3bea4baac9a5a, 0xe9da8d699b94184a, 0xcdb13f4cd93e024c, 0x902cbd0956f655e3, 0x5b4e40ffc759532f, 0xde795c20a2357af7],
];

pub const TERMINAL_EXTERNAL_CONSTANTS: [[u64; 12]; 4] = [
    [0x7b72c539e0ea4c6e, 0x144573dae2ce9976, 0x802028b68f35fc88, 0x6d36c5022c4fe7c2, 0xa205d0ffa9b9def3, 0xf6e7e38b1ea6ba2f, 0x34f7909ae5258d64, 0xb0464d9d77b97fca, 0x64ddb9d5de7e00a6, 0x0ed0d75c27975d97, 0x1cbb36f11127338b, 0x6673e505cfd0b6ba],
    [0x605f902830872e01, 0x3fd5eb927e95fe4f, 0xe81025b5a24c69cd, 0xf7d0ce75de23f74e, 0xf39942b6a8585089, 0x6d808a08f7b71df6, 0xf8806b6588f49a8b, 0x57df2d8c2a32107a, 0x16e7c2074d654a2d, 0x213de241fcf33835, 0xb0f2b8905a0976f6, 0xd8e3cf2bbd355417],
    [0xe498691679d9330f, 0x763b45d2a3821b28, 0x0908bf65eb0a1f0d, 0x7691eb2d194b24f4, 0x0e43551233ae13b2, 0x93c393dbfc2fe76f, 0x98f607485d48cdea, 0xe3d95f30309819c0, 0x1ef581a93eaf6acf, 0x0b24c1b7a030fca4, 0x624370be5670b327, 0x5f1e28615a11e486],
    [0xfe04051f909e042b, 0x7257e5b147fd3803, 0xe6ae134bb82f2e78, 0x5711fd5cf4784511, 0xf83a42660c08c0bc, 0x2cd8c96d9a3ce855, 0x7d2ffb1bb0e17271, 0x85ae1528caea3811, 0x52a345d5c7adb0b8, 0x504c4c51f3faee94, 0xbce34a649cfccaf9, 0xe0a3389266fb6dc9],
];

/// qp-poseidon `apply_mat4`: multiply a length-4 chunk by [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
#[inline]
fn apply_mat4(x: &mut [u64]) {
    let t01 = add(x[0], x[1]);
    let t23 = add(x[2], x[3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[1]);
    let t01233 = add(t0123, x[3]);
    x[3] = add(t01233, double(x[0]));
    x[1] = add(t01123, double(x[2]));
    x[0] = add(t01123, t01);
    x[2] = add(t01233, t23);
}

/// External (full) linear layer: mat4 on each 4-block, then add the per-lane
/// block sums `sums[i % 4]`.
fn external_linear_layer(state: &mut [u64; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        apply_mat4(chunk);
    }
    let sums: [u64; 4] = std::array::from_fn(|k| add(add(state[k], state[4 + k]), state[8 + k]));
    for i in 0..WIDTH {
        state[i] = add(state[i], sums[i % 4]);
    }
}

/// Internal (partial) linear layer: `state[i] = sum(state) + state[i] * diag[i]`.
fn internal_linear_layer(state: &mut [u64; WIDTH]) {
    let mut sum = 0u64;
    for &s in state.iter() {
        sum = add(sum, s);
    }
    for i in 0..WIDTH {
        state[i] = add(sum, mul(state[i], MATRIX_DIAG[i]));
    }
}

#[inline]
fn external_round(state: &mut [u64; WIDTH], rc: &[u64; WIDTH]) {
    for i in 0..WIDTH {
        state[i] = exp7(add(state[i], rc[i]));
    }
    external_linear_layer(state);
}

#[inline]
fn internal_round(state: &mut [u64; WIDTH], rc: u64) {
    state[0] = exp7(add(state[0], rc));
    internal_linear_layer(state);
}

/// Full Poseidon2 permutation, reduced-round aware.
/// `ext_init`, `n_int`, `ext_term` select how many of the initial-external,
/// internal, and terminal-external rounds to run. Full = (4, 22, 4).
/// The pre-round external linear layer always runs (as in qp-poseidon).
pub fn permute_rounds(state: &mut [u64; WIDTH], ext_init: usize, n_int: usize, ext_term: usize) {
    external_linear_layer(state);
    for r in 0..ext_init {
        external_round(state, &INITIAL_EXTERNAL_CONSTANTS[r]);
    }
    for r in 0..n_int {
        internal_round(state, INTERNAL_CONSTANTS[r]);
    }
    for r in 0..ext_term {
        external_round(state, &TERMINAL_EXTERNAL_CONSTANTS[r]);
    }
}

/// Full permutation (4, 22, 4).
#[inline]
pub fn permute(state: &mut [u64; WIDTH]) {
    permute_rounds(state, HALF_EXTERNAL_ROUNDS, INTERNAL_ROUNDS, HALF_EXTERNAL_ROUNDS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::P;

    #[test]
    fn constants_canonical() {
        for c in INTERNAL_CONSTANTS {
            assert!(c < P);
        }
        for c in MATRIX_DIAG {
            assert!(c < P);
        }
        for row in INITIAL_EXTERNAL_CONSTANTS.iter().chain(TERMINAL_EXTERNAL_CONSTANTS.iter()) {
            for &c in row {
                assert!(c < P);
            }
        }
    }

    #[test]
    fn mat4_known_answer() {
        let mut x = [1u64, 2, 3, 4];
        apply_mat4(&mut x);
        assert_eq!(x, [15, 18, 21, 16]);
    }

    #[test]
    fn external_linear_layer_known_answer() {
        let mut s: [u64; 12] = std::array::from_fn(|i| (i + 1) as u64);
        external_linear_layer(&mut s);
        assert_eq!(
            s,
            [144, 156, 168, 148, 172, 184, 196, 176, 200, 212, 224, 204]
        );
    }

    #[test]
    fn permute_zero_state() {
        let mut s = [0u64; 12];
        permute(&mut s);
        assert_eq!(
            s,
            [
                0xc9bc9432e1686884, 0x03ecbab0dcdd2189, 0x5e7ac885b3dc1215, 0x6ac07513801d191f,
                0xca5c593fb184dcfc, 0x414dec5f3e455287, 0x1a17df170127ae41, 0xe7e592bd0af9b0a5,
                0xc71a9b27edc66a4c, 0x2728671759ac43c2, 0xb9969c20f7f672f9, 0xc5140b586823b92f,
            ]
        );
    }

    #[test]
    fn permute_seq_state() {
        let mut s: [u64; 12] = std::array::from_fn(|i| (i + 1) as u64);
        permute(&mut s);
        assert_eq!(
            s,
            [
                0x7e9574e2a3d6c48b, 0x9d7bc16d282d2f2b, 0x798826626d94a498, 0x0831011bb22304c7,
                0xbdccb5931fffd16c, 0xe98687714dacbefc, 0xc6a1ed29dd75e027, 0x1aec96681d15f765,
                0xc74b2c710b170a23, 0x5fb4aff45e9c24fb, 0x1fb3d228db0127eb, 0xe201a7e214b16e74,
            ]
        );
    }
}
