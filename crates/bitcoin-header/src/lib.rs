//! Bitcoin block header engine.
//!
//! Byte order conventions:
//! * Hashes are stored in *internal* byte order (the raw SHA-256d digest).
//!   RPC and block explorers display them reversed; see [`display_hex`].
//! * [`Target`] stores a 256-bit number big-endian, so derived `Ord` is
//!   numeric order. A block hash is compared as the little-endian number its
//!   internal bytes encode (`Target::from_hash`).

#![forbid(unsafe_code)]

pub mod block;

use sha256_core::{IV, ROUNDS, State, block_words, compress_words, digest_bytes};
use sha256d::sha256d;

pub const HEADER_LEN: usize = 80;

/// Compact `nBits` of the main-network proof-of-work limit.
pub const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00ffff;
/// Compact `nBits` of the regtest proof-of-work limit.
pub const REGTEST_POW_LIMIT_BITS: u32 = 0x207fffff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Hex(String),
    Length { expected: usize, got: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Hex(s) => write!(f, "invalid hex: {s}"),
            Error::Length { expected, got } => write!(f, "expected {expected} bytes, got {got}"),
        }
    }
}

impl std::error::Error for Error {}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(Error::Hex(format!("odd length {}", s.len())));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| Error::Hex(e.to_string())))
        .collect()
}

fn decode_exact<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    let v = hex_decode(s)?;
    let got = v.len();
    v.try_into().map_err(|_| Error::Length { expected: N, got })
}

/// Hash in internal byte order to the reversed hex used by RPC/explorers.
pub fn display_hex(internal: &[u8; 32]) -> String {
    let mut r = *internal;
    r.reverse();
    hex_encode(&r)
}

/// Reversed (display) hex to internal byte order.
pub fn parse_display_hex(s: &str) -> Result<[u8; 32], Error> {
    let mut b: [u8; 32] = decode_exact(s)?;
    b.reverse();
    Ok(b)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    /// Internal byte order.
    pub prev_blockhash: [u8; 32],
    /// Internal byte order.
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// Consensus serialization: all integers little-endian, hashes raw.
    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.prev_blockhash);
        b[36..68].copy_from_slice(&self.merkle_root);
        b[68..72].copy_from_slice(&self.time.to_le_bytes());
        b[72..76].copy_from_slice(&self.bits.to_le_bytes());
        b[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn deserialize(b: &[u8; HEADER_LEN]) -> Self {
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Self {
            version: u32_at(0) as i32,
            prev_blockhash: b[4..36].try_into().expect("32 bytes"),
            merkle_root: b[36..68].try_into().expect("32 bytes"),
            time: u32_at(68),
            bits: u32_at(72),
            nonce: u32_at(76),
        }
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        Ok(Self::deserialize(&decode_exact(s)?))
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.serialize())
    }

    /// SHA-256d of the serialized header, internal byte order.
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }

    pub fn block_hash_hex(&self) -> String {
        display_hex(&self.hash())
    }
}

/// Result of decoding compact `nBits`, mirroring Bitcoin Core's `SetCompact`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compact {
    pub target: Target,
    pub negative: bool,
    pub overflow: bool,
}

/// 256-bit unsigned number, big-endian bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target(pub [u8; 32]);

impl Target {
    pub const ZERO: Target = Target([0; 32]);

    /// Bitcoin Core `arith_uint256::SetCompact`.
    pub fn from_compact(bits: u32) -> Compact {
        let size = (bits >> 24) as usize;
        let mut word = bits & 0x007f_ffff;
        let mut t = [0u8; 32];
        let shift = if size <= 3 {
            word >>= 8 * (3 - size) as u32;
            0
        } else {
            size - 3
        };
        // `word * 256^shift`; bytes beyond 2^256 are dropped as in Core.
        for (j, byte) in word.to_le_bytes()[..3].iter().enumerate() {
            let power = shift + j;
            if power < 32 {
                t[31 - power] = *byte;
            }
        }
        Compact {
            target: Target(t),
            negative: word != 0 && bits & 0x0080_0000 != 0,
            overflow: word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)),
        }
    }

    /// Bitcoin Core `arith_uint256::GetCompact(false)`.
    pub fn to_compact(&self) -> u32 {
        let first = self.0.iter().position(|&b| b != 0);
        let Some(first) = first else { return 0 };
        let mut size = (32 - first) as u32;
        let byte = |i: usize| self.0.get(i).copied().unwrap_or(0) as u32;
        let mut compact = if size <= 3 {
            let mut v = 0u32;
            for i in first..32 {
                v = (v << 8) | byte(i);
            }
            v << (8 * (3 - size))
        } else {
            (byte(first) << 16) | (byte(first + 1) << 8) | byte(first + 2)
        };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact | (size << 24)
    }

    /// The number a hash (internal byte order) encodes as little-endian.
    pub fn from_hash(internal: &[u8; 32]) -> Self {
        let mut b = *internal;
        b.reverse();
        Target(b)
    }

    /// `hash <= target`, the proof-of-work condition.
    pub fn is_met_by(&self, hash_internal: &[u8; 32]) -> bool {
        Target::from_hash(hash_internal) <= *self
    }

    /// Big-endian 32-bit words, most significant first (kernel format).
    pub fn words(&self) -> [u32; 8] {
        std::array::from_fn(|i| u32::from_be_bytes(self.0[4 * i..4 * i + 4].try_into().expect("4 bytes")))
    }

    pub fn from_words(words: [u32; 8]) -> Self {
        let mut b = [0u8; 32];
        for (chunk, w) in b.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        Target(b)
    }

    /// Big-endian hex, the format of `getblocktemplate`'s `target`.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        Ok(Target(decode_exact(s)?))
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Number of leading zero bits (256 for zero).
    pub fn leading_zeros(&self) -> u32 {
        let mut n = 0;
        for w in self.words() {
            n += w.leading_zeros();
            if w != 0 {
                break;
            }
        }
        n
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowError {
    Negative,
    Zero,
    Overflow,
    AboveLimit,
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Bitcoin Core `CheckProofOfWork`: `Err` when `bits` itself is invalid,
/// otherwise whether `hash <= target`.
pub fn check_proof_of_work(hash_internal: &[u8; 32], bits: u32, pow_limit_bits: u32) -> Result<bool, PowError> {
    let c = Target::from_compact(bits);
    if c.negative {
        return Err(PowError::Negative);
    }
    if c.overflow {
        return Err(PowError::Overflow);
    }
    if c.target == Target::ZERO {
        return Err(PowError::Zero);
    }
    if c.target > Target::from_compact(pow_limit_bits).target {
        return Err(PowError::AboveLimit);
    }
    Ok(c.target.is_met_by(hash_internal))
}

/// Hash words `H0..H7` (as produced by the compression function) to the
/// big-endian words of the number they encode, most significant first.
#[inline(always)]
pub fn hash_number_words(h: &State) -> [u32; 8] {
    std::array::from_fn(|i| h[7 - i].swap_bytes())
}

/// Cached first-block compression of an 80-byte header.
///
/// The first 64 header bytes never change during nonce search, so their
/// compression (the *midstate*) is computed once; each nonce then needs only
/// the second block and the outer hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderMidstate {
    pub state: State,
    /// Big-endian words of header bytes 64..76 (merkle tail, time, bits).
    pub tail: [u32; 3],
    pub rounds: usize,
}

impl HeaderMidstate {
    pub fn new(header: &[u8; HEADER_LEN]) -> Self {
        Self::with_rounds(header, ROUNDS)
    }

    /// Reduced-round variant: all three compression calls use `rounds`.
    pub fn with_rounds(header: &[u8; HEADER_LEN], rounds: usize) -> Self {
        let first: &[u8; 64] = header[..64].try_into().expect("64 bytes");
        let be = |i: usize| u32::from_be_bytes(header[i..i + 4].try_into().expect("4 bytes"));
        Self { state: compress_words(&IV, &block_words(first), rounds), tail: [be(64), be(68), be(72)], rounds }
    }

    /// Second padded block. The nonce is serialized little-endian, so its
    /// big-endian message word is `nonce.swap_bytes()`.
    #[inline]
    pub fn second_block(&self, nonce: u32) -> [u32; 16] {
        let mut m = [0u32; 16];
        m[..3].copy_from_slice(&self.tail);
        m[3] = nonce.swap_bytes();
        m[4] = 0x8000_0000;
        m[15] = 640; // 80 bytes in bits
        m
    }

    /// Final state words of SHA-256d(header with `nonce`).
    pub fn hash_words(&self, nonce: u32) -> State {
        let inner = compress_words(&self.state, &self.second_block(nonce), self.rounds);
        let mut m = [0u32; 16];
        m[..8].copy_from_slice(&inner);
        m[8] = 0x8000_0000;
        m[15] = 256; // 32 bytes in bits
        compress_words(&IV, &m, self.rounds)
    }

    /// SHA-256d(header with `nonce`), internal byte order.
    pub fn hash(&self, nonce: u32) -> [u8; 32] {
        digest_bytes(&self.hash_words(nonce))
    }
}

/// Merkle root over transaction ids (internal byte order). Odd levels
/// duplicate their last element, as in Bitcoin Core.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    assert!(!txids.is_empty(), "a block has at least one transaction");
    let mut level = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                sha256d(&buf)
            })
            .collect();
    }
    level[0]
}

/// Real main-network headers used as validation fixtures. Their hashes were
/// produced by Bitcoin Core and each satisfies its own encoded target, which a
/// transcription error would not.
pub mod fixtures {
    pub struct KnownHeader {
        pub height: u32,
        pub header_hex: &'static str,
        pub hash: &'static str,
        pub version: i32,
        pub time: u32,
        pub bits: u32,
        pub nonce: u32,
    }

    pub const MAINNET: &[KnownHeader] = &[
        KnownHeader {
            height: 0,
            header_hex: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            version: 1,
            time: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        },
        KnownHeader {
            height: 1,
            header_hex: "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            hash: "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            version: 1,
            time: 1231469665,
            bits: 0x1d00ffff,
            nonce: 2573394689,
        },
        KnownHeader {
            height: 125552,
            header_hex: "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695",
            hash: "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d",
            version: 1,
            time: 1305998791,
            bits: 0x1a44b9f2,
            nonce: 2504433986,
        },
    ];

    /// Block 100000, built from its fields and its four transaction ids
    /// (display order) to exercise merkle construction end to end.
    pub const BLOCK_100000_PREV: &str = "000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250";
    pub const BLOCK_100000_MERKLE: &str = "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766";
    pub const BLOCK_100000_HASH: &str = "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506";
    pub const BLOCK_100000_TIME: u32 = 1293623863;
    pub const BLOCK_100000_BITS: u32 = 0x1b04864c;
    pub const BLOCK_100000_NONCE: u32 = 274148111;
    pub const BLOCK_100000_TXIDS: [&str; 4] = [
        "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
        "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
        "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
        "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_headers_roundtrip_hash_and_pow() {
        for k in fixtures::MAINNET {
            let h = BlockHeader::from_hex(k.header_hex).unwrap();
            assert_eq!(h.to_hex(), k.header_hex);
            assert_eq!((h.version, h.time, h.bits, h.nonce), (k.version, k.time, k.bits, k.nonce), "height {}", k.height);
            assert_eq!(h.block_hash_hex(), k.hash, "height {}", k.height);
            assert_eq!(check_proof_of_work(&h.hash(), h.bits, MAINNET_POW_LIMIT_BITS), Ok(true));
            let mid = HeaderMidstate::new(&h.serialize());
            assert_eq!(mid.hash(h.nonce), h.hash());
            assert!(!Target::from_compact(h.bits).target.is_met_by(&mid.hash(h.nonce.wrapping_add(1))));
        }
    }

    #[test]
    fn block_100000_from_fields_and_txids() {
        use fixtures::*;
        let txids: Vec<[u8; 32]> = BLOCK_100000_TXIDS.iter().map(|t| parse_display_hex(t).unwrap()).collect();
        let merkle = merkle_root(&txids);
        assert_eq!(display_hex(&merkle), BLOCK_100000_MERKLE);
        let h = BlockHeader {
            version: 1,
            prev_blockhash: parse_display_hex(BLOCK_100000_PREV).unwrap(),
            merkle_root: merkle,
            time: BLOCK_100000_TIME,
            bits: BLOCK_100000_BITS,
            nonce: BLOCK_100000_NONCE,
        };
        assert_eq!(h.block_hash_hex(), BLOCK_100000_HASH);
        assert_eq!(check_proof_of_work(&h.hash(), h.bits, MAINNET_POW_LIMIT_BITS), Ok(true));
    }

    // Cases from Bitcoin Core src/test/arith_uint256_tests.cpp (bignum_SetCompact).
    #[test]
    fn compact_decoding_matches_core() {
        let t = |hex: &str| {
            let mut b = [0u8; 32];
            let v = hex_decode(&format!("{hex:0>64}")).unwrap();
            b.copy_from_slice(&v);
            Target(b)
        };
        let cases: &[(u32, &str, u32, bool)] = &[
            (0x00000000, "0", 0, false),
            (0x00123456, "0", 0, false),
            (0x01003456, "0", 0, false),
            (0x02000056, "0", 0, false),
            (0x03000000, "0", 0, false),
            (0x04000000, "0", 0, false),
            (0x00923456, "0", 0, false),
            (0x01803456, "0", 0, false),
            (0x02800056, "0", 0, false),
            (0x03800000, "0", 0, false),
            (0x04800000, "0", 0, false),
            (0x01123456, "12", 0x01120000, false),
            (0x01fedcba, "7e", 0x017e0000, true),
            (0x02123456, "1234", 0x02123400, false),
            (0x03123456, "123456", 0x03123456, false),
            (0x04123456, "12345600", 0x04123456, false),
            (0x04923456, "12345600", 0x04123456, true),
            (0x05009234, "92340000", 0x05009234, false),
            (0x20123456, "1234560000000000000000000000000000000000000000000000000000000000", 0x20123456, false),
        ];
        for &(bits, value, recompact, negative) in cases {
            let c = Target::from_compact(bits);
            assert_eq!(c.target, t(value), "bits {bits:#010x}");
            assert_eq!(c.negative, negative, "bits {bits:#010x}");
            assert!(!c.overflow, "bits {bits:#010x}");
            assert_eq!(c.target.to_compact(), recompact, "bits {bits:#010x}");
        }
        assert!(Target::from_compact(0xff123456).overflow);
        // GetCompact never sets the sign bit.
        assert_eq!(t("80").to_compact(), 0x02008000);
    }

    #[test]
    fn pow_limit_checks() {
        let zero_hash = [0u8; 32];
        assert_eq!(check_proof_of_work(&zero_hash, 0x04923456, MAINNET_POW_LIMIT_BITS), Err(PowError::Negative));
        assert_eq!(check_proof_of_work(&zero_hash, 0, MAINNET_POW_LIMIT_BITS), Err(PowError::Zero));
        assert_eq!(check_proof_of_work(&zero_hash, 0xff123456, MAINNET_POW_LIMIT_BITS), Err(PowError::Overflow));
        assert_eq!(check_proof_of_work(&zero_hash, REGTEST_POW_LIMIT_BITS, MAINNET_POW_LIMIT_BITS), Err(PowError::AboveLimit));
        assert_eq!(check_proof_of_work(&zero_hash, REGTEST_POW_LIMIT_BITS, REGTEST_POW_LIMIT_BITS), Ok(true));
        assert_eq!(check_proof_of_work(&[0xff; 32], REGTEST_POW_LIMIT_BITS, REGTEST_POW_LIMIT_BITS), Ok(false));
    }

    #[test]
    fn target_ordering_and_words() {
        let limit = Target::from_compact(MAINNET_POW_LIMIT_BITS).target;
        assert_eq!(limit.words(), [0, 0xffff0000, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Target::from_words(limit.words()), limit);
        assert_eq!(limit.leading_zeros(), 32);
        let mut h = [0u8; 32];
        h[31] = 1; // hash number = 2^248
        assert!(Target::from_hash(&h) > limit);
    }

    #[test]
    fn number_words_match_target_comparison() {
        let header = BlockHeader::from_hex(fixtures::MAINNET[2].header_hex).unwrap();
        let mid = HeaderMidstate::new(&header.serialize());
        let words = mid.hash_words(header.nonce);
        assert_eq!(Target::from_words(hash_number_words(&words)), Target::from_hash(&mid.hash(header.nonce)));
    }
}
