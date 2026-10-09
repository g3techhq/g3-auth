use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::post,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;

use super::{
    APPLE_CALLBACK_PATH, APPLE_PREPARE_PATH, AppleChallenge, ApplePrepare, AppleSignedIn, tokens,
};
use crate::{AuthUser, PublicEndpoint, SessionContext};

// Both run before there is a session, so the guard has to let them through.
// Registered here, beside the routes, so mounting the router and opening the
// paths are one decision.
inventory::submit!(PublicEndpoint::new(APPLE_PREPARE_PATH));
inventory::submit!(PublicEndpoint::new(APPLE_CALLBACK_PATH));

/// Who Apple says the visitor is. Only `subject` is guaranteed.
#[derive(Clone, Debug)]
pub struct AppleIdentity {
    /// Apple's stable account id (`sub`). Key accounts on this, never on the
    /// email, which can be a private relay address.
    pub subject: String,
    /// The email in the signed identity token, if any. Apple shares it with
    /// the first authorization, and the token repeats it.
    pub email: Option<String>,
    /// Whether Apple has verified [`email`](Self::email).
    pub email_verified: bool,
    /// The name, only on the first authorization and only if the visitor
    /// shared it. It is not signed, so use it for display and nothing else.
    pub name: Option<String>,
    /// The Apple client the token was issued to (the Services ID or the bundle
    /// id). [`revoke_token`] needs it back.
    pub client_id: String,
    /// The refresh token, when a signing key is configured. Keep it with the
    /// account and hand it to [`revoke_token`] when the account is deleted.
    pub refresh_token: Option<String>,
}

/// The account an Apple identity maps to.
#[derive(Clone, Debug)]
pub struct AppleAccount {
    /// The account record's key (`k3j2h1` for `user:k3j2h1`).
    pub user_id: String,
    /// Whether this sign-in created the account.
    pub is_new: bool,
}

/// Finds or creates the app's account for a verified Apple identity.
#[async_trait]
pub trait AppleAccounts<C: Connection>: Send + Sync + 'static {
    /// The account for `identity`, created if there is none yet. Look it up by
    /// [`AppleIdentity::subject`], and bind values rather than formatting them
    /// into the query. Store the refresh token if you want to revoke it later.
    async fn find_or_create(
        &self,
        db: &Surreal<C>,
        identity: AppleIdentity,
    ) -> anyhow::Result<AppleAccount>;

    /// Where to send the visitor when the attempt finishes, or `None` for
    /// [`AppleConfig`]'s signed-in or new-account path. `return_to` is what the
    /// button was given, which the client controls: allow only paths of your
    /// own app, or this is an open redirect.
    fn destination(&self, _is_new: bool, _return_to: Option<&str>) -> Option<String> {
        None
    }
}

/// Where the callback sends the visitor, and which Apple clients it trusts.
#[derive(Clone, Debug)]
pub struct AppleConfig {
    signed_in_path: String,
    new_account_path: String,
    services_id: Option<String>,
    native_client_id: Option<String>,
    origin: Option<String>,
}

impl AppleConfig {
    /// `signed_in_path` is where a returning visitor lands, `new_account_path`
    /// where a new account goes to finish its profile. Everything else comes
    /// from the environment; see the [module](super) docs.
    pub fn new(signed_in_path: impl Into<String>, new_account_path: impl Into<String>) -> Self {
        Self {
            signed_in_path: signed_in_path.into(),
            new_account_path: new_account_path.into(),
            services_id: None,
            native_client_id: None,
            origin: None,
        }
    }

    /// Use this Services ID instead of `APPLE_SERVICES_ID`.
    #[must_use]
    pub fn services_id(mut self, services_id: impl Into<String>) -> Self {
        self.services_id = Some(services_id.into());
        self
    }

    /// The iOS app's bundle id, the audience of native tokens, instead of
    /// `APPLE_BUNDLE_ID`.
    #[must_use]
    pub fn native_client_id(mut self, bundle_id: impl Into<String>) -> Self {
        self.native_client_id = Some(bundle_id.into());
        self
    }

    /// The public origin Apple returns to, instead of `APP_ORIGIN`.
    #[must_use]
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    fn resolved_services_id(&self) -> Option<String> {
        self.services_id
            .clone()
            .or_else(|| tokens::env("APPLE_SERVICES_ID"))
    }

    fn resolved_native_client_id(&self) -> Option<String> {
        self.native_client_id
            .clone()
            .or_else(|| tokens::env("APPLE_BUNDLE_ID"))
    }

    fn redirect_uri(&self) -> String {
        let origin = self
            .origin
            .clone()
            .or_else(|| tokens::env("APP_ORIGIN"))
            .unwrap_or_else(|| "http://localhost:8080".into());
        format!("{}{APPLE_CALLBACK_PATH}", origin.trim_end_matches('/'))
    }
}

struct Inner<C: Connection> {
    config: AppleConfig,
    accounts: Box<dyn AppleAccounts<C>>,
}

/// The routes behind the button. Merge it **before** the session, auth and
/// guard layers, which only wrap the routes registered ahead of them:
///
/// ```ignore
/// dioxus::server::router(App)
///     .merge(apple_router::<AppUser, Client, _>(config, MyAccounts))
///     .layer(Extension(db))
///     .layer(from_fn_with_state(guard, require_session::<AppUser, Client>))
///     .layer(AuthSessionLayer::<AppUser, Client>::new(Some(db)))
///     .layer(SessionLayer::new(store))
/// ```
///
/// A browser is redirected to the signed-in (or new-account) path; a request
/// sending `Accept: application/json`, which is how the iOS flow calls it, gets
/// an [`AppleSignedIn`] instead. A browser post must carry the `apple_state`
/// cookie the button set; see [`csrf`](crate::csrf).
pub fn apple_router<U, C, A>(config: AppleConfig, accounts: A) -> Router
where
    U: AuthUser,
    C: Connection,
    A: AppleAccounts<C>,
{
    let inner = Arc::new(Inner::<C> {
        config,
        accounts: Box::new(accounts),
    });
    let prepare = Router::new().route(APPLE_PREPARE_PATH, post(prepare::<U, C>));
    let callback = crate::csrf::protect(
        Router::new().route(APPLE_CALLBACK_PATH, post(callback::<U, C>)),
        crate::csrf::DoubleSubmit::APPLE,
    );
    prepare.merge(callback).with_state(inner)
}

/// Revokes an Apple refresh token, for when the account that holds it is
/// deleted. App Store review (guideline 5.1.1(v)) expects a deleted account to
/// stop being linked to Apple. Needs the signing key.
pub async fn revoke_token(client_id: &str, refresh_token: &str) -> anyhow::Result<()> {
    tokens::revoke(client_id, refresh_token).await
}

#[derive(Deserialize, SurrealValue)]
struct Challenge {
    nonce: String,
    native: bool,
    redirect_uri: Option<String>,
    return_to: Option<String>,
}

async fn prepare<U, C>(
    State(inner): State<Arc<Inner<C>>>,
    context: SessionContext<U, C>,
    body: Option<Json<ApplePrepare>>,
) -> Response
where
    U: AuthUser,
    C: Connection,
{
    let ApplePrepare { native, return_to } = body.map(|Json(body)| body).unwrap_or_default();
    // Opaque to us, but bounded: it is stored and handed back to the app.
    let return_to = return_to.filter(|value| value.len() <= MAX_RETURN_TO);
    let Some(services_id) = inner.config.resolved_services_id() else {
        return (
            StatusCode::NOT_FOUND,
            "Sign in with Apple is not configured.",
        )
            .into_response();
    };
    let redirect_uri = (!native).then(|| inner.config.redirect_uri());
    match issue(&context.db, native, redirect_uri.clone(), return_to).await {
        Ok(Some(issued)) => Json(AppleChallenge {
            services_id,
            redirect_uri: redirect_uri.unwrap_or_default(),
            state: issued.state,
            nonce: issued.nonce,
        })
        .into_response(),
        Ok(None) | Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not start Sign in with Apple.",
        )
            .into_response(),
    }
}

/// The longest `return_to` the server will keep.
const MAX_RETURN_TO: usize = 512;

/// Starts an attempt, sweeping the ones that expired.
async fn issue<C: Connection>(
    db: &Surreal<C>,
    native: bool,
    redirect_uri: Option<String>,
    return_to: Option<String>,
) -> surrealdb::Result<Option<Issued>> {
    db.query(
        "DELETE apple_challenge WHERE expires_at < time::now(); \
         CREATE apple_challenge SET state = rand::string(40), nonce = rand::string(40), \
         native = $native, redirect_uri = $redirect_uri, return_to = $return_to, expires_at = time::now() + 10m \
         RETURN state, nonce;",
    )
    .bind(("native", native))
    .bind(("redirect_uri", redirect_uri))
    .bind(("return_to", return_to))
    .await?
    .take::<Option<Issued>>(1)
}

/// Ends an attempt. Single use: a replayed or expired `state` finds nothing.
async fn consume<C: Connection>(
    db: &Surreal<C>,
    state: &str,
) -> surrealdb::Result<Option<Challenge>> {
    Ok(db
        .query("DELETE apple_challenge WHERE state = $state AND expires_at > time::now() RETURN BEFORE")
        .bind(("state", state.to_owned()))
        .await?
        .take::<Vec<Challenge>>(0)?
        .into_iter()
        .next())
}

#[derive(Deserialize, SurrealValue)]
struct Issued {
    state: String,
    nonce: String,
}

/// Apple's web form fields, and the native plugin's envelope in `credential`.
#[derive(Deserialize)]
struct CallbackForm {
    code: Option<String>,
    id_token: Option<String>,
    state: Option<String>,
    user: Option<String>,
    credential: Option<String>,
}

/// What the iOS plugin returns.
#[derive(Deserialize)]
struct NativeCredential {
    identity_token: String,
    authorization_code: String,
    state: String,
    display_name: Option<String>,
}

/// Apple's first-authorization `user` field (web). Unsigned.
#[derive(Deserialize)]
struct UserField {
    name: Option<UserName>,
}

#[derive(Deserialize)]
struct UserName {
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
}

/// The fields of a callback, whichever way it arrived.
#[derive(Debug, PartialEq, Eq)]
struct Presented {
    code: Option<String>,
    id_token: Option<String>,
    state: String,
    name: Option<String>,
}

fn present(form: CallbackForm) -> Result<Presented, String> {
    if let Some(raw) = form.credential {
        let native: NativeCredential = serde_json::from_str(&raw)
            .map_err(|_| "The Apple credential is malformed.".to_string())?;
        return Ok(Presented {
            code: Some(native.authorization_code),
            id_token: Some(native.identity_token),
            state: native.state,
            name: native.display_name,
        });
    }
    let name = form
        .user
        .as_deref()
        .and_then(|raw| serde_json::from_str::<UserField>(raw).ok())
        .and_then(|user| user.name)
        .map(|name| {
            [name.first_name, name.last_name]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ")
        });
    Ok(Presented {
        code: form.code,
        id_token: form.id_token,
        state: form
            .state
            .ok_or_else(|| "The Apple callback has no state.".to_string())?,
        name,
    })
}

/// The nonce the identity token must carry: native tokens hold its SHA-256 hex.
fn expected_nonce(nonce: &str, native: bool) -> String {
    if native {
        hex::encode(Sha256::digest(nonce.as_bytes()))
    } else {
        nonce.to_string()
    }
}

/// A shared name is trimmed, collapsed and bounded; an empty one is no name.
fn clean_name(name: Option<String>) -> Option<String> {
    let name = name?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

async fn callback<U, C>(
    State(inner): State<Arc<Inner<C>>>,
    context: SessionContext<U, C>,
    headers: HeaderMap,
    Form(form): Form<CallbackForm>,
) -> Response
where
    U: AuthUser,
    C: Connection,
{
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("application/json"));
    match sign_in(&inner, &context, form).await {
        Ok(signed_in) if wants_json => Json(signed_in).into_response(),
        Ok(signed_in) => Redirect::to(&signed_in.destination).into_response(),
        Err(message) => {
            // The reason can name a token; keep it in the log, not the page.
            eprintln!("Sign in with Apple failed: {message}");
            (
                StatusCode::BAD_REQUEST,
                "Sign in with Apple could not be completed.",
            )
                .into_response()
        }
    }
}

async fn sign_in<U, C>(
    inner: &Inner<C>,
    context: &SessionContext<U, C>,
    form: CallbackForm,
) -> Result<AppleSignedIn, String>
where
    U: AuthUser,
    C: Connection,
{
    let presented = present(form)?;

    let challenge = consume(&context.db, &presented.state)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("The sign-in attempt expired or was already used.")?;

    // The challenge, not the request, says which Apple client this is.
    let client_id = if challenge.native {
        inner
            .config
            .resolved_native_client_id()
            .ok_or("APPLE_BUNDLE_ID is not configured.")?
    } else {
        inner
            .config
            .resolved_services_id()
            .ok_or("APPLE_SERVICES_ID is not configured.")?
    };
    let nonce = expected_nonce(&challenge.nonce, challenge.native);

    let (claims, refresh_token) = if tokens::key_configured() && presented.code.is_some() {
        // Apple vouches for the code itself, so the token it returns is the one
        // that counts. A token posted beside it must be the same account's.
        let code = presented.code.as_deref().unwrap_or_default();
        let exchanged = tokens::exchange_code(&client_id, code, challenge.redirect_uri.as_deref())
            .await
            .map_err(|error| error.to_string())?;
        let claims = tokens::verify(&exchanged.id_token, &client_id, &nonce)
            .await
            .map_err(|error| error.to_string())?;
        if let Some(posted) = presented.id_token.as_deref() {
            let posted = tokens::verify(posted, &client_id, &nonce)
                .await
                .map_err(|error| error.to_string())?;
            if posted.sub != claims.sub {
                return Err("The code and the identity token belong to different accounts.".into());
            }
        }
        (claims, exchanged.refresh_token)
    } else {
        let token = presented
            .id_token
            .as_deref()
            .ok_or("The Apple callback has no identity token.")?;
        (
            tokens::verify(token, &client_id, &nonce)
                .await
                .map_err(|error| error.to_string())?,
            None,
        )
    };

    let account = inner
        .accounts
        .find_or_create(
            &context.db,
            AppleIdentity {
                email_verified: claims.email_is_verified(),
                subject: claims.sub,
                email: claims.email,
                name: clean_name(presented.name),
                client_id,
                refresh_token,
            },
        )
        .await
        .map_err(|error| error.to_string())?;

    context.auth_session.login_user(account.user_id);
    context.auth_session.remember_user(true);
    let destination = inner
        .accounts
        .destination(account.is_new, challenge.return_to.as_deref())
        .unwrap_or_else(|| {
            if account.is_new {
                inner.config.new_account_path.clone()
            } else {
                inner.config.signed_in_path.clone()
            }
        });
    Ok(AppleSignedIn {
        destination,
        is_new: account.is_new,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(credential: Option<&str>, state: Option<&str>, user: Option<&str>) -> CallbackForm {
        CallbackForm {
            code: Some("c".into()),
            id_token: Some("t".into()),
            state: state.map(str::to_owned),
            user: user.map(str::to_owned),
            credential: credential.map(str::to_owned),
        }
    }

    use surrealdb::engine::local::{Db, Mem};

    async fn database() -> Surreal<Db> {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory database");
        db.use_ns("test").use_db("test").await.expect("namespace");
        db.query(crate::APPLE_SCHEMA)
            .await
            .expect("schema")
            .check()
            .expect("schema applies");
        db
    }

    #[tokio::test]
    async fn a_challenge_is_single_use() {
        let db = database().await;
        let issued = issue(
            &db,
            false,
            Some("https://a.example/cb".into()),
            Some("/games".into()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(issued.state.len(), 40);
        assert_ne!(issued.state, issued.nonce);

        let taken = consume(&db, &issued.state)
            .await
            .unwrap()
            .expect("first use");
        assert_eq!(taken.nonce, issued.nonce);
        assert!(!taken.native);
        assert_eq!(taken.return_to.as_deref(), Some("/games"));
        assert_eq!(taken.redirect_uri.as_deref(), Some("https://a.example/cb"));
        assert!(
            consume(&db, &issued.state).await.unwrap().is_none(),
            "a replay finds nothing"
        );
        assert!(consume(&db, "never-issued").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_expired_challenge_is_refused_and_swept() {
        let db = database().await;
        let issued = issue(&db, true, None, None).await.unwrap().unwrap();
        db.query("UPDATE apple_challenge SET expires_at = time::now() - 1s")
            .await
            .unwrap()
            .check()
            .unwrap();
        assert!(consume(&db, &issued.state).await.unwrap().is_none());
        issue(&db, false, None, None).await.unwrap().unwrap();
        let left: Vec<serde_json::Value> = db
            .query("SELECT * FROM apple_challenge")
            .await
            .unwrap()
            .take(0)
            .unwrap();
        assert_eq!(left.len(), 1, "issuing swept the expired attempt");
    }

    #[test]
    fn the_callbacks_are_public_because_they_are_how_a_visitor_signs_in() {
        assert!(crate::is_public_endpoint(APPLE_PREPARE_PATH));
        assert!(crate::is_public_endpoint(APPLE_CALLBACK_PATH));
        assert!(!crate::is_public_endpoint(
            "/api/v1/apple_signin_callback/extra"
        ));
    }

    #[test]
    fn a_web_post_reads_state_and_the_unsigned_name() {
        let presented = present(form(
            None,
            Some("s"),
            Some(r#"{"name":{"firstName":"Avery","lastName":"Green"},"email":"x@y.z"}"#),
        ))
        .unwrap();
        assert_eq!(presented.state, "s");
        assert_eq!(presented.name.as_deref(), Some("Avery Green"));
        assert!(present(form(None, None, None)).is_err());
    }

    #[test]
    fn a_native_post_reads_the_plugin_envelope() {
        let presented = present(form(
            Some(r#"{"identity_token":"t","authorization_code":"c","state":"s","display_name":"Avery"}"#),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(presented.state, "s");
        assert_eq!(presented.name.as_deref(), Some("Avery"));
        assert!(present(form(Some("not json"), None, None)).is_err());
    }

    #[test]
    fn native_tokens_carry_the_hashed_nonce() {
        assert_eq!(expected_nonce("n", false), "n");
        assert_eq!(
            expected_nonce("nonce", true),
            "78377b525757b494427f89014f97d79928f3938d14eb51e20fb5dec9834eb304"
        );
    }

    #[test]
    fn names_are_collapsed_and_bounded() {
        assert_eq!(
            clean_name(Some("  Avery\n Green ".into())).as_deref(),
            Some("Avery Green")
        );
        assert_eq!(clean_name(Some("   ".into())), None);
        assert_eq!(clean_name(None), None);
        assert_eq!(clean_name(Some("x".repeat(100))).unwrap().len(), 80);
    }
}
