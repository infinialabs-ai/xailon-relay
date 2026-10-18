//! Channel authentication, shared by the server and its tests. The client
//! side lives in `relay-client::auth`; keep the two in sync.
//!
//! A channel id is not a credential: it travels in connect URLs. A client
//! opens the socket with `auth=1` and sends a 32-byte token in its first
//! frame. Self-certifying ids (`xrc1_…`) are the SHA-256 of the token, so the
//! relay checks the token against the id. Any other id is claimed by its first
//! authenticated connection, and the relay stores only a verifier of the
//! token.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub const CHANNEL_ID_PREFIX: &str = "xrc1_";
const CHANNEL_LABEL: &[u8] = b"xailon-relay/channel/v1\0";
const VERIFIER_LABEL: &[u8] = b"xailon-relay/verifier/v1\0";

/// `xrc1_` + base64url(SHA-256("xailon-relay/channel/v1" || 0x00 || token)).
pub fn channel_id(token: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(CHANNEL_LABEL)
        .chain_update(token)
        .finalize();
    format!("{CHANNEL_ID_PREFIX}{}", URL_SAFE_NO_PAD.encode(digest))
}

pub fn is_self_certifying(relay_id: &str) -> bool {
    relay_id.starts_with(CHANNEL_ID_PREFIX)
}

/// Decodes the wire form of a token (base64url, no padding, 32 bytes).
pub fn decode_token(token: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(token).ok()?.try_into().ok()
}

/// Hex verifier stored for a claimed channel: SHA-256 over a label, the
/// channel id and the token, so one token's verifier is useless elsewhere.
pub fn verifier(relay_id: &str, token: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(VERIFIER_LABEL)
        .chain_update(relay_id.as_bytes())
        .chain_update([0])
        .chain_update(token)
        .finalize();
    format!("{digest:x}")
}

/// Compares in time independent of where the inputs differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Short, non-reversible label for logs, so log readers never learn ids.
pub fn log_label(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{:x}", digest)[..12].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_client_vector() {
        assert_eq!(
            channel_id(&[7; 32]),
            "xrc1_oX-L9_s96NXsgVBg8cm-GlxQmamMTtRQxfPhAsVvgz8"
        );
        assert_eq!(
            decode_token("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"),
            Some([7; 32])
        );
        assert_eq!(decode_token("BwcH"), None);
        assert_eq!(decode_token("not base64!"), None);
    }

    #[test]
    fn verifier_is_bound_to_the_channel() {
        assert_ne!(verifier("a", &[1; 32]), verifier("b", &[1; 32]));
        assert_ne!(verifier("a", &[1; 32]), verifier("a", &[2; 32]));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
