//! Stable internal identifiers.
//!
//! Identifiers are 16 random bytes from the OS CSPRNG. They carry no user
//! meaning and are never derived from filenames or content.

use vault_crypto::random_bytes;

pub type Id = [u8; 16];

pub fn new_id() -> Id {
    random_bytes()
}

pub fn id_hex(id: &Id) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn parse_id_hex(s: &str) -> Option<Id> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let id = new_id();
        let hex = id_hex(&id);
        assert_eq!(hex.len(), 32);
        assert_eq!(parse_id_hex(&hex), Some(id));
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(parse_id_hex("zz").is_none());
        assert!(parse_id_hex(&"a".repeat(31)).is_none());
        assert!(parse_id_hex(&"g".repeat(32)).is_none());
    }
}
