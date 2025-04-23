use std::{
    collections::BTreeMap,
    ops::Add,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::RandomizedDigestSigner;
use http::uri::Uri;
use p256::ecdsa;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::trace;

use crate::{error::WebPushError, vapid::VapidKey};

/// A struct representing a VAPID signature. Should be generated using the
/// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VapidSignature {
    /// The signed JWT, base64-encoded
    pub auth_t: String,
    /// The public key bytes
    pub auth_k: Vec<u8>,
}

/// JWT claims object. Custom claims are implemented as a map.
// pub type Claims = JWTClaims<BTreeMap<String /*Use String as lifetimes bug out when serializing a tuple*/, Value>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    #[serde(flatten)]
    pub custom: BTreeMap<String, Value>,
}

impl Claims {
    pub fn set_audience(&mut self, aud: String) {
        self.aud = Some(aud);
    }
    pub fn set_sub(&mut self, sub: String) {
        self.sub = Some(sub);
    }
    pub fn set_exp(&mut self, exp: u64) {
        self.exp = Some(exp);
    }
    pub fn now() -> Claims {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .add(Duration::from_secs(12 * 60 * 60))
            .as_secs();

        Claims {
            exp: Some(exp),
            sub: None,
            aud: None,
            custom: Default::default(),
        }
    }
}

pub struct VapidSigner {}

impl VapidSigner {
    /// Create a signature with a given key. Sets the default audience from the
    /// endpoint host and sets the expiry in twelve hours. Values can be
    /// overwritten by adding the `aud` and `exp` claims.
    pub fn sign(key: VapidKey, endpoint: &Uri, mut claims: Claims) -> Result<VapidSignature, WebPushError> {
        if claims.aud.is_none() {
            //Add audience if not provided.
            let audience = format!("{}://{}", endpoint.scheme_str().unwrap(), endpoint.host().unwrap());
            claims.aud = Some(audience);
        }

        // Add sub if not provided as some browsers (like firefox) require it even though the API doesn't say its needed >:[
        if claims.sub.is_none() {
            claims.sub = Some("mailto:example@example.com".to_string());
        }

        trace!("Using jwt: {:?}", claims);

        //Generate JWT signature

        let header = json! ({"alg": "ES256", "typ":"JWT"});
        let partial_jwt = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(serde_json::to_string(&header).unwrap().as_bytes()),
            Base64UrlUnpadded::encode_string(serde_json::to_string(&claims).unwrap().as_bytes()),
        );
        let mut digest = Sha256::new();
        digest.update(partial_jwt.as_bytes());
        let mut rng = rand::thread_rng();
        let signature: ecdsa::Signature = key.0.try_sign_digest_with_rng(&mut rng, digest).unwrap();
        let mut auth_t = partial_jwt;
        auth_t.push('.');
        auth_t.push_str(&Base64UrlUnpadded::encode_string(&signature.to_vec()));

        Ok(VapidSignature {
            auth_t,
            auth_k: key.public_key(),
        })
    }
}

#[cfg(test)]
mod tests {}
