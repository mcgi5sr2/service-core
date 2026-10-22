//! BFF-trust: a short-lived assertion a trusted upstream (a backend-for-frontend)
//! signs to vouch for an end user to a backend service, so the service need not
//! re-validate the identity provider on the hot path.
//!
//! The shared contract: the upstream [`mint`]s an assertion, the service
//! [`BffTrust::verify`]s it and gets back the same [`Claims`] a normal bearer
//! yields, so a handler's `AuthenticatedUser` is identical either way. This is the
//! alternative path to identity that [`crate::auth`] reserved — added without any
//! change to consumer handler code.
//!
//! Trust model: the assertion is an RS256 JWT signed with the upstream's private
//! key, `aud` = the target service, short TTL. The service is configured with the
//! upstream's PUBLIC key (non-secret) and its issuer. Forging one needs the private
//! key; a leaked assertion is near-useless (single audience, seconds of validity).
//! The public key is distributed as static config rather than via a JWKS endpoint —
//! smaller surface; JWKS-based rotation is a later add.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::Serialize;

use crate::auth::Claims;

/// Header carrying the assertion — kept distinct from the `Authorization` bearer so
/// the two paths never collide and an upstream can send both during a transition.
pub const ASSERTION_HEADER: &str = "X-Bff-Assertion";

fn now_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as usize)
        .unwrap_or(0)
}

/// The assertion wire format. Verified back into [`Claims`] (which ignores the
/// extra `aud`/`iss`/`iat` — those are checked by the validator, not the struct).
#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    aud: &'a str,
    exp: usize,
    iat: usize,
    /// Carried through so a service can still gate step-up actions on `auth_time`.
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<usize>,
}

/// Mint an assertion for `aud` (the target service) that expires in `ttl`. The
/// upstream calls this per proxied request; keep `ttl` short.
pub fn mint(
    claims: &Claims,
    aud: &str,
    issuer: &str,
    ttl: Duration,
    key: &EncodingKey,
    kid: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let iat = now_secs();
    let body = AssertionClaims {
        iss: issuer,
        sub: &claims.sub,
        email: claims.email.as_deref(),
        aud,
        exp: iat + ttl.as_secs() as usize,
        iat,
        auth_time: claims.auth_time,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, &body, key)
}

/// The service-side verifier: the upstream's public key plus the identifiers to
/// insist on. Held on a service's `JwksStore` via
/// [`crate::auth::JwksStore::with_bff_trust`], so enabling BFF-trust is a
/// constructor choice, not a handler change.
pub struct BffTrust {
    issuer: String,
    /// This service's own audience — the upstream sets the assertion `aud` to it.
    audience: String,
    key: DecodingKey,
}

impl BffTrust {
    /// `public_key_pem` is the upstream's RSA public key (SPKI PEM, non-secret).
    pub fn new(issuer: String, audience: String, public_key_pem: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            issuer,
            audience,
            key: DecodingKey::from_rsa_pem(public_key_pem)?,
        })
    }

    /// Verify an assertion → the same [`Claims`] a bearer token yields. Fail-closed:
    /// any failure (bad signature, wrong issuer/audience, expired) is a `401`.
    pub fn verify(&self, token: &str) -> Result<Claims, StatusCode> {
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.audience]);
        decode::<Claims>(token, &self.key, &v)
            .map(|d| d.claims)
            .map_err(|e| {
                tracing::warn!("bff-trust: assertion validation failed: {e}");
                StatusCode::UNAUTHORIZED
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway 2048-bit RSA keypair, for tests only.
    const PRIV: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzdxLUkiLHpis7
QO3sYdlcIPxjjphR9Fe3CmBugAeKLx/2RFlleIWfZLLrzAAbyho7l4gYATZXqv3l
rjL6ttUJN5OLdQwLHiQZBXLOjMn+64BnWVHxGaXAVjCCnTnMetjNzu1pOoMr/VB2
Mn54Vi5BMN3PeBpApLJpngr3AI8fEySEy0TiG6hJv/b/7hb7HTVbt+pKAejY0AUf
ot2SrNnGu3ja571KFf86CDaHwWO4qiJzYsTFlcuS6dsUBzCorkWuNAfXGASrNywL
yqFlHInYtAiS30jZU2eerFDlwz9yX61q73k9Fa74EQEOFpoivc0KwmzCEE8LUoZ1
e4NTz+tVAgMBAAECggEAFtNkxjumB82nPvyVplSVsEWTxFfdIMNaqrG7rSJEkztG
Lezoj+Lh3/GPXjVOqDou1viBe0ggMMtTSrS60C+T7f2vGvQyqXFWdwY94W5/vJgY
d0yhgvBXqBxuRBaaRNs1GwwgHxutllk8NCRc+JJBhNIhzCMC98ja1lsfGuZrzbBL
VXyp96XMvWzUjroK/5VuvV8fd/pGrCa9LXwuwf/cfIEueO7G6BFl51n31NcxBfJE
qLx5Igt2ftny74m7Hm3OHZSycRUmpH9DxkQsZk5OHkDqwBGodCnVEFQiUlHJtc7Z
Adq9TGR+7pYgYmK2rNStiKVKHZpsN/k+JE1ozULrCwKBgQDryiw4RbNpN7vT6Nwc
cweEzkEa0wAHrfs16cCqIzYF1XUHaxF73V+qX7IyT+pQBItUpWZxBqFFFQF1FLh7
UrCgfQAwUNiBkRGcsXiaa0LnQP3a0CAl/qLlU76AHybFofq1Nn+aLnH+oDlIL95F
vXvtk0aJWVdOxMpiVQks1knILwKBgQDC2P7bVt30IEuLBJAq2mEzWIFlRmXna2AU
C2nFis8/i9AYVnn8ex9GeNRMdWrChwqfdcbUsJQ6Al7Um2VqQWaWPSur+0X8RZd6
VFk5YAHis8Ao+FeHSbw/07Lnv/VuqaJSjanGLSh6RajLimN6amf1wPPXZ2qNfhdN
N9EgleMfuwKBgQCPF5ZWYBZNGEGojHxn13cMpY7lFH/EKVV2lnERz2SNjckDw3pM
zT+tSX3/AniULu3PZMESfo+IOQM1Zmm+jaQbAUEIEUgS+VLS4PDr5YQoi0yDaiLY
a/u3aGcHoeAJuA9JwdUWYHFVsS6SHFqrwB5hQytfVxSg/NRFcI2s5C7KiQKBgFWs
M+MdftoomQ63Iuy0uKhq8folygjHHaeynP9O2XGHeCg7Xce2GzpRRoeX2SlPV0xl
7Nb4DTS0dh3ldeISf5jvrJQiF9OkhcYz8EdZ/3o+ru9UwqeptCwcWT2tGa1eyRCj
WVLZ6EJa/q0AXF0nDC7yeETuI9uy5Wv+buV1AjihAoGBAIb4blHNeIsQ/T+UfhDd
jTw7m6gGPoQIWXLdFceaYEHGiVEx2UBsXNz15fkGTuxuFV+ubF7YVSGhGVhogAvD
9iJrGvRKKtdRctMA+62mevEDlmg8p6O5aJ4Rw+AT75e67xny65KRprI0K4gPgkl3
lli9ofnruMB5eiN8uoVthwpk
-----END PRIVATE KEY-----";

    const PUB: &[u8] = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3cS1JIix6YrO0Dt7GHZ
XCD8Y46YUfRXtwpgboAHii8f9kRZZXiFn2Sy68wAG8oaO5eIGAE2V6r95a4y+rbV
CTeTi3UMCx4kGQVyzozJ/uuAZ1lR8RmlwFYwgp05zHrYzc7taTqDK/1QdjJ+eFYu
QTDdz3gaQKSyaZ4K9wCPHxMkhMtE4huoSb/2/+4W+x01W7fqSgHo2NAFH6LdkqzZ
xrt42ue9ShX/Ogg2h8FjuKoic2LExZXLkunbFAcwqK5FrjQH1xgEqzcsC8qhZRyJ
2LQIkt9I2VNnnqxQ5cM/cl+tau95PRWu+BEBDhaaIr3NCsJswhBPC1KGdXuDU8/r
VQIDAQAB
-----END PUBLIC KEY-----";

    fn claims() -> Claims {
        Claims {
            sub: "user-1".into(),
            email: Some("u@example".into()),
            exp: 0,
            auth_time: Some(1000),
        }
    }

    fn enc() -> EncodingKey {
        EncodingKey::from_rsa_pem(PRIV).unwrap()
    }

    #[test]
    fn mint_then_verify_roundtrips_to_the_same_identity() {
        let token = mint(&claims(), "svc-a", "bff", Duration::from_secs(60), &enc(), "k1").unwrap();
        let trust = BffTrust::new("bff".into(), "svc-a".into(), PUB).unwrap();
        let out = trust.verify(&token).unwrap();
        assert_eq!(out.sub, "user-1");
        assert_eq!(out.email.as_deref(), Some("u@example"));
        assert_eq!(out.auth_time, Some(1000));
    }

    #[test]
    fn rejects_the_wrong_audience() {
        // Minted for svc-a, presented to a verifier expecting svc-b.
        let token = mint(&claims(), "svc-a", "bff", Duration::from_secs(60), &enc(), "k1").unwrap();
        let trust = BffTrust::new("bff".into(), "svc-b".into(), PUB).unwrap();
        assert_eq!(trust.verify(&token).unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rejects_the_wrong_issuer() {
        let token = mint(&claims(), "svc-a", "not-the-bff", Duration::from_secs(60), &enc(), "k1").unwrap();
        let trust = BffTrust::new("bff".into(), "svc-a".into(), PUB).unwrap();
        assert_eq!(trust.verify(&token).unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rejects_an_expired_assertion() {
        // ttl 0 → exp == now; after a moment the no-leeway validator must reject it.
        let token = mint(&claims(), "svc-a", "bff", Duration::from_secs(0), &enc(), "k1").unwrap();
        let trust = BffTrust::new("bff".into(), "svc-a".into(), PUB).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&["bff"]);
        v.set_audience(&["svc-a"]);
        v.leeway = 0;
        std::thread::sleep(Duration::from_millis(1100));
        assert!(decode::<Claims>(&token, &trust.key, &v).is_err());
    }

    #[test]
    fn rejects_a_signature_from_a_different_key() {
        // A token this verifier's key did not sign must fail — the forgery guard.
        let token = mint(&claims(), "svc-a", "bff", Duration::from_secs(60), &enc(), "k1").unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_string();
        let tampered = format!("{}x", &sig[..sig.len() - 1]);
        parts[2] = &tampered;
        let forged = parts.join(".");
        let trust = BffTrust::new("bff".into(), "svc-a".into(), PUB).unwrap();
        assert_eq!(trust.verify(&forged).unwrap_err(), StatusCode::UNAUTHORIZED);
    }
}
