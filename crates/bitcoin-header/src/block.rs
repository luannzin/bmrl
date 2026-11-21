//! Minimal transaction and block encoding needed to assemble a candidate
//! block from a `getblocktemplate` response: script numbers, the coinbase
//! transaction (BIP34 height, optional BIP141 witness commitment) and the
//! block wire format.

use crate::BlockHeader;
use sha256d::sha256d;

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Bitcoin Core `CScriptNum::serialize`.
pub fn script_num(value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    let negative = value < 0;
    let mut abs = value.unsigned_abs();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if let Some(last) = out.last_mut() {
        if *last & 0x80 != 0 {
            out.push(if negative { 0x80 } else { 0 });
        } else if negative {
            *last |= 0x80;
        }
    }
    out
}

/// Bitcoin Core `CScript::operator<<(std::vector<unsigned char>)`.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        n if n < 0x4c => script.push(n as u8),
        n if n <= 0xff => script.extend_from_slice(&[0x4c, n as u8]),
        n if n <= 0xffff => {
            script.push(0x4d);
            script.extend_from_slice(&(n as u16).to_le_bytes());
        }
        n => {
            script.push(0x4e);
            script.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

/// Bitcoin Core `CScript::operator<<(int64_t)`: small integers use OP_N.
pub fn push_int(script: &mut Vec<u8>, n: i64) {
    match n {
        0 => script.push(0x00),
        -1 => script.push(0x4f),
        1..=16 => script.push(0x50 + n as u8),
        _ => push_data(script, &script_num(n)),
    }
}

/// Coinbase transaction for a template.
#[derive(Clone, Debug)]
pub struct Coinbase {
    pub height: i64,
    /// Satoshis: subsidy plus template fees (`coinbasevalue`).
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    /// Varied to change the merkle root once the nonce space is exhausted.
    pub extra_nonce: u64,
    /// Arbitrary tag pushed after the extra nonce.
    pub tag: Vec<u8>,
    /// Full witness-commitment output script (`default_witness_commitment`).
    pub witness_commitment: Option<Vec<u8>>,
}

impl Coinbase {
    /// BIP34 height push, extra nonce, tag. Consensus requires 2..=100 bytes.
    pub fn script_sig(&self) -> Vec<u8> {
        let mut s = Vec::new();
        push_int(&mut s, self.height);
        push_data(&mut s, &self.extra_nonce.to_le_bytes());
        push_data(&mut s, &self.tag);
        assert!((2..=100).contains(&s.len()), "coinbase scriptSig must be 2..=100 bytes, got {}", s.len());
        s
    }

    /// Wire serialization. With a witness commitment the coinbase carries the
    /// 32-byte zero witness reserved value (BIP141).
    pub fn serialize(&self, with_witness: bool) -> Vec<u8> {
        let segwit = with_witness && self.witness_commitment.is_some();
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        if segwit {
            tx.extend_from_slice(&[0x00, 0x01]);
        }
        tx.push(1);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        let script_sig = self.script_sig();
        write_varint(&mut tx, script_sig.len() as u64);
        tx.extend_from_slice(&script_sig);
        // nSequence/nLockTime as Bitcoin Core's miner sets them (BIP54-compatible):
        // non-final sequence, lock time = height - 1 (always already final).
        tx.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
        let mut outputs = vec![(self.value, self.script_pubkey.as_slice())];
        if let Some(c) = &self.witness_commitment {
            outputs.push((0, c.as_slice()));
        }
        write_varint(&mut tx, outputs.len() as u64);
        for (value, script) in outputs {
            tx.extend_from_slice(&value.to_le_bytes());
            write_varint(&mut tx, script.len() as u64);
            tx.extend_from_slice(script);
        }
        if segwit {
            tx.push(1);
            tx.push(32);
            tx.extend_from_slice(&[0u8; 32]);
        }
        tx.extend_from_slice(&((self.height.max(1) - 1) as u32).to_le_bytes());
        tx
    }

    /// Transaction id (non-witness serialization), internal byte order.
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize(false))
    }
}

/// Block wire format: header, transaction count, transactions.
pub fn serialize_block(header: &BlockHeader, transactions: &[Vec<u8>]) -> Vec<u8> {
    let mut out = header.serialize().to_vec();
    write_varint(&mut out, transactions.len() as u64);
    for tx in transactions {
        out.extend_from_slice(tx);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_numbers_match_core() {
        assert_eq!(script_num(0), Vec::<u8>::new());
        assert_eq!(script_num(1), vec![0x01]);
        assert_eq!(script_num(-1), vec![0x81]);
        assert_eq!(script_num(127), vec![0x7f]);
        assert_eq!(script_num(128), vec![0x80, 0x00]);
        assert_eq!(script_num(-128), vec![0x80, 0x80]);
        assert_eq!(script_num(255), vec![0xff, 0x00]);
        assert_eq!(script_num(256), vec![0x00, 0x01]);
        assert_eq!(script_num(500_000), vec![0x20, 0xa1, 0x07]);
    }

    #[test]
    fn bip34_height_pushes() {
        let mut s = Vec::new();
        push_int(&mut s, 1);
        assert_eq!(s, vec![0x51]);
        s.clear();
        push_int(&mut s, 17);
        assert_eq!(s, vec![0x01, 0x11]);
        s.clear();
        push_int(&mut s, 227_836);
        assert_eq!(s, vec![0x03, 0xfc, 0x79, 0x03]);
    }

    #[test]
    fn varints() {
        let enc = |n| {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            v
        };
        assert_eq!(enc(0xfc), vec![0xfc]);
        assert_eq!(enc(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(enc(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn witness_serialization_only_changes_wtxid() {
        let cb = Coinbase {
            height: 5,
            value: 50_0000_0000,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            extra_nonce: 7,
            tag: b"bmrl".to_vec(),
            witness_commitment: Some(vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        };
        let legacy = cb.serialize(false);
        let segwit = cb.serialize(true);
        assert_eq!(segwit.len(), legacy.len() + 2 + 1 + 1 + 32);
        assert_eq!(cb.txid(), sha256d(&legacy));
    }
}
