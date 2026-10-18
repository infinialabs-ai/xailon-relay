//! Channel authentication.
//!
//! A channel id alone is not a credential: it appears in connect URLs, so
//! proxies and access logs see it. A client that holds a 32-byte channel auth
//! token sends it as the first frame (never in the URL). The relay binds the
//! channel to the token:
//!
//! - **Self-certifying ids** (`xrc1_…`, from [`channel_id`]) are the SHA-256 of
//!   the token, so the relay checks the token against the id itself and keeps
//!   no state. Nobody can claim such a channel without the token.
//! - **Other ids** are claimed by the first authenticated connection; the
//!   relay stores a hash of the token and refuses every later connection that
//!   does not present it.
//!
//! Derive the token from a secret both endpoints already share (for example
//! the pairing secret, with HKDF and a distinct label), never from the id.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Prefix of self-certifying channel ids.
pub const CHANNEL_ID_PREFIX: &str = "xrc1_";
const CHANNEL_LABEL: &[u8] = b"xailon-relay/channel/v1\0";

/// The self-certifying channel id for `token`:
/// `xrc1_` + base64url(SHA-256("xailon-relay/channel/v1" || 0x00 || token)).
pub fn channel_id(token: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(CHANNEL_LABEL)
        .chain_update(token)
        .finalize();
    format!("{CHANNEL_ID_PREFIX}{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Wire form of a token: base64url without padding.
pub fn encode_token(token: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_matches_vector() {
        // Shared with client-ts and the Cloudflare Worker tests.
        assert_eq!(
            channel_id(&[7; 32]),
            "xrc1_oX-L9_s96NXsgVBg8cm-GlxQmamMTtRQxfPhAsVvgz8"
        );
        assert_eq!(
            encode_token(&[7; 32]),
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        );
    }
}
