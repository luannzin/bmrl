//! SHA-256d: `SHA-256(SHA-256(x))`, the hash Bitcoin uses for block headers,
//! transaction ids and merkle nodes.

#![forbid(unsafe_code)]

use sha256_core::sha256;

/// Double SHA-256.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_vectors() {
        assert_eq!(hex(&sha256d(b"")), "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
        assert_eq!(hex(&sha256d(b"hello")), "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
    }
}
