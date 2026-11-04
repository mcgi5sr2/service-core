//! The fixture signing key and helpers the tests' fake identity providers share.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;

pub const KEY_PEM: &str = include_str!("../fixtures/test-only-idp-signing-key.pem");
/// Modulus of the fixture key, base64url — what a fake provider publishes.
pub const KEY_N: &str = "sC266YSK7l34lFj1Z5DSRt0cbrNinMqqXJvc8K-NDggPFEn1TYdlT1y6XAxILhz9phJo1RUigKz9Zw_1mTTciL8At0Liiy6PxmwS2tn4I6CJBwmw9f-5XQQA-qKuDrFjmUMoNaXE6RNwHenH2mfx_uq7OJiC4H2l32306_LzxaWVjq2doKEd35ElSlIzH1KMARKom_ZTpthJADv2QZr7uyqJxfJciWwlsdkEMgpCbS2gJ2t3hZNl1rFi8rk4WYcZjTd6nO_TQqcPYucloDcAvL3mxMxH7vFdX6xONJujSKyvYJ7VRMM02_jLBasi1664Uy7JDu1_QbeVsrcp-67ltQ";

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Signs `claims` with the fixture key under `kid`.
pub fn sign(kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_pem(KEY_PEM.as_bytes()).unwrap()).unwrap()
}
