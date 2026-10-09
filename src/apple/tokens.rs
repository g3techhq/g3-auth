//! Talking to Apple: identity-token verification, the code exchange and
//! revocation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    jwk::JwkSet,
};
use serde::{Deserialize, Serialize};

pub(super) const ISSUER: &str = "https://appleid.apple.com";

/// The claims this crate reads from an identity token.
#[derive(Debug, Deserialize)]
pub(super) struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<serde_json::Value>,
    pub nonce: Option<String>,
}

impl Claims {
    /// Apple sends the flag as a boolean or as the string `"true"`.
    pub fn email_is_verified(&self) -> bool {
        match &self.email_verified {
            Some(serde_json::Value::Bool(value)) => *value,
            Some(serde_json::Value::String(value)) => value == "true",
            _ => false,
        }
    }
}

/// Picks the JWT crypto backend. `jsonwebtoken` refuses to guess when two are
/// compiled in, and SurrealDB turns on `aws_lc_rs` in the same graph, so an app
/// that also asks for `rust_crypto` would panic here on the first sign-in.
/// Installing one is harmless when the app already did.
fn ensure_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

pub(super) fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?)
}

/// Checks `token`'s signature against `key`, and its issuer, audience, expiry
/// and nonce. `expected_nonce` is the value the token must carry.
pub(super) fn verify_with_key(
    token: &str,
    key: &DecodingKey,
    audience: &str,
    expected_nonce: &str,
) -> Result<Claims> {
    ensure_provider();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<Claims>(token, key, &validation)?.claims;
    if claims.nonce.as_deref() != Some(expected_nonce) {
        bail!("the identity token's nonce does not match the challenge");
    }
    Ok(claims)
}

/// Fetches Apple's signing keys and verifies `token` with the one it names.
pub(super) async fn verify(token: &str, audience: &str, expected_nonce: &str) -> Result<Claims> {
    let kid = decode_header(token)?
        .kid
        .ok_or_else(|| anyhow!("the identity token has no key id"))?;
    let keys = http()?
        .get(format!("{ISSUER}/auth/keys"))
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    let jwk = keys
        .find(&kid)
        .ok_or_else(|| anyhow!("the identity token names an unknown signing key"))?;
    verify_with_key(
        token,
        &DecodingKey::from_jwk(jwk)?,
        audience,
        expected_nonce,
    )
}

/// The sign-in key from the environment, if one is configured.
fn private_key() -> Result<Option<Vec<u8>>> {
    let inline = env("APPLE_PRIVATE_KEY");
    let path = env("APPLE_PRIVATE_KEY_PATH");
    if inline.is_some() && path.is_some() {
        bail!("configure only one of APPLE_PRIVATE_KEY or APPLE_PRIVATE_KEY_PATH");
    }
    if let Some(value) = inline {
        return Ok(Some(value.replace("\\n", "\n").into_bytes()));
    }
    path.map(|path| std::fs::read(&path).with_context(|| format!("reading {path}")))
        .transpose()
}

/// Whether the environment holds a complete Sign in with Apple key.
pub(super) fn key_configured() -> bool {
    env("APPLE_TEAM_ID").is_some()
        && env("APPLE_KEY_ID").is_some()
        && (env("APPLE_PRIVATE_KEY").is_some() || env("APPLE_PRIVATE_KEY_PATH").is_some())
}

/// The short-lived JWT that authenticates this app to Apple's token endpoints.
fn client_secret(client_id: &str) -> Result<String> {
    #[derive(Serialize)]
    struct SecretClaims<'a> {
        iss: &'a str,
        iat: u64,
        exp: u64,
        aud: &'a str,
        sub: &'a str,
    }

    let team = env("APPLE_TEAM_ID").ok_or_else(|| anyhow!("APPLE_TEAM_ID is not configured"))?;
    let key_id = env("APPLE_KEY_ID").ok_or_else(|| anyhow!("APPLE_KEY_ID is not configured"))?;
    let pem = private_key()?.ok_or_else(|| anyhow!("APPLE_PRIVATE_KEY is not configured"))?;
    ensure_provider();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id);
    Ok(encode(
        &header,
        &SecretClaims {
            iss: &team,
            iat: now,
            exp: now + 300,
            aud: ISSUER,
            sub: client_id,
        },
        &EncodingKey::from_ec_pem(&pem)?,
    )?)
}

/// What Apple's token endpoint returns for an authorization code.
pub(super) struct Exchanged {
    pub id_token: String,
    pub refresh_token: Option<String>,
}

pub(super) async fn exchange_code(
    client_id: &str,
    code: &str,
    redirect_uri: Option<&str>,
) -> Result<Exchanged> {
    #[derive(Deserialize)]
    struct Response {
        id_token: Option<String>,
        refresh_token: Option<String>,
        error: Option<String>,
    }

    let secret = client_secret(client_id)?;
    let mut form = vec![
        ("client_id", client_id),
        ("client_secret", secret.as_str()),
        ("code", code),
        ("grant_type", "authorization_code"),
    ];
    if let Some(redirect_uri) = redirect_uri {
        form.push(("redirect_uri", redirect_uri));
    }
    let response = http()?
        .post(format!("{ISSUER}/auth/token"))
        .form(&form)
        .send()
        .await?;
    let status = response.status();
    let body: Response = response.json().await?;
    if !status.is_success() {
        bail!(
            "Apple rejected the authorization code: {}",
            body.error.unwrap_or_else(|| status.to_string())
        );
    }
    Ok(Exchanged {
        id_token: body
            .id_token
            .ok_or_else(|| anyhow!("Apple's token response had no identity token"))?,
        refresh_token: body.refresh_token,
    })
}

pub(super) async fn revoke(client_id: &str, refresh_token: &str) -> Result<()> {
    let secret = client_secret(client_id)?;
    http()?
        .post(format!("{ISSUER}/auth/revoke"))
        .form(&[
            ("client_id", client_id),
            ("client_secret", secret.as_str()),
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway keys made for these tests; they sign nothing real.
    const SIGNER: &str = include_str!("test_keys/signer.pem");
    const SIGNER_PUBLIC: &str = include_str!("test_keys/signer.pub.pem");
    const OTHER: &str = include_str!("test_keys/other.pem");

    const AUDIENCE: &str = "com.example.services";
    const NONCE: &str = "the-nonce";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn token_with(pem: &str, claims: serde_json::Value) -> String {
        ensure_provider();
        encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn claims(overrides: serde_json::Value) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "001234.abc",
            "exp": now() + 600,
            "iat": now(),
            "nonce": NONCE,
            "email": "avery@example.com",
            "email_verified": "true",
        });
        for (key, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(key);
            } else {
                claims[key] = value.clone();
            }
        }
        claims
    }

    fn check(token: &str) -> Result<Claims> {
        let key = DecodingKey::from_rsa_pem(SIGNER_PUBLIC.as_bytes()).unwrap();
        verify_with_key(token, &key, AUDIENCE, NONCE)
    }

    #[test]
    fn a_genuine_token_verifies_and_reads_the_string_flag() {
        let claims = check(&token_with(SIGNER, claims(serde_json::json!({})))).unwrap();
        assert_eq!(claims.sub, "001234.abc");
        assert_eq!(claims.email.as_deref(), Some("avery@example.com"));
        assert!(claims.email_is_verified());
    }

    #[test]
    fn the_verified_flag_is_a_boolean_or_the_string_true_and_nothing_else() {
        let flag = |value: serde_json::Value| {
            check(&token_with(
                SIGNER,
                claims(serde_json::json!({ "email_verified": value })),
            ))
            .unwrap()
            .email_is_verified()
        };
        assert!(flag(serde_json::json!(true)));
        assert!(flag(serde_json::json!("true")));
        assert!(!flag(serde_json::json!(false)));
        assert!(!flag(serde_json::json!("false")));
        assert!(!flag(serde_json::json!(1)));
        assert!(
            !check(&token_with(
                SIGNER,
                claims(serde_json::json!({ "email_verified": null }))
            ))
            .unwrap()
            .email_is_verified()
        );
    }

    #[test]
    fn a_token_is_refused_for_every_way_it_can_be_wrong() {
        let refused = |token: String| assert!(check(&token).is_err());
        // Someone else's key.
        refused(token_with(OTHER, claims(serde_json::json!({}))));
        // Another app's audience, another issuer, expired, a replayed nonce.
        refused(token_with(
            SIGNER,
            claims(serde_json::json!({ "aud": "com.example.other" })),
        ));
        refused(token_with(
            SIGNER,
            claims(serde_json::json!({ "iss": "https://evil.example" })),
        ));
        refused(token_with(
            SIGNER,
            claims(serde_json::json!({ "exp": now() - 3600 })),
        ));
        refused(token_with(
            SIGNER,
            claims(serde_json::json!({ "nonce": "another" })),
        ));
        refused(token_with(
            SIGNER,
            claims(serde_json::json!({ "nonce": null })),
        ));
        refused(token_with(
            SIGNER,
            claims(serde_json::json!({ "sub": null })),
        ));
    }

    #[test]
    fn a_token_signed_with_the_public_key_as_an_hmac_secret_is_refused() {
        // The classic algorithm-confusion forgery.
        ensure_provider();
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims(serde_json::json!({})),
            &EncodingKey::from_secret(SIGNER_PUBLIC.as_bytes()),
        )
        .unwrap();
        assert!(check(&forged).is_err());
    }

    #[test]
    fn the_client_secret_needs_a_complete_key() {
        // No Apple key is configured in the test environment.
        if !key_configured() {
            assert!(client_secret("com.example.services").is_err());
        }
    }
}
