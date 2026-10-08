use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Form, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::post,
};
use surrealdb::{Connection, Surreal};

use super::{GOOGLE_CALLBACK_PATH, GoogleCallback, GoogleSignedIn};
use crate::{AuthUser, PublicEndpoint, SessionContext};

// The callback is how a signed-out visitor becomes signed in, so the guard
// has to let it through. Registered here, beside the route, so that mounting
// the router and opening the path are one decision.
inventory::submit!(PublicEndpoint::new(GOOGLE_CALLBACK_PATH));

/// Who Google says the visitor is. Only `subject` is guaranteed; the rest is
/// whatever the account shares.
#[derive(Clone, Debug)]
pub struct GoogleIdentity {
    /// Google's stable account id (`sub`). Key accounts on this, never on
    /// the email, which can change.
    pub subject: String,
    /// The account's email, if shared.
    pub email: Option<String>,
    /// Whether Google has verified [`email`](Self::email).
    pub email_verified: bool,
    /// The display name, if shared.
    pub name: Option<String>,
    /// A profile picture URL, if shared.
    pub picture: Option<String>,
}

/// The account a Google identity maps to.
#[derive(Clone, Debug)]
pub struct GoogleAccount {
    /// The account record's key (`k3j2h1` for `user:k3j2h1`), which the
    /// session stores.
    pub user_id: String,
    /// Whether the account was created by this sign-in, which sends the
    /// visitor to [`GoogleConfig`]'s new-account path to finish a profile.
    pub is_new: bool,
}

/// Finds or creates the app's account for a verified Google identity. This is
/// the one app-specific part: the account table's required fields are the
/// app's.
#[async_trait]
pub trait GoogleAccounts<C: Connection>: Send + Sync + 'static {
    /// The account for `identity`, created if there is none yet. Look it up
    /// by [`GoogleIdentity::subject`], and bind values rather than formatting
    /// them into the query.
    async fn find_or_create(
        &self,
        db: &Surreal<C>,
        identity: GoogleIdentity,
    ) -> anyhow::Result<GoogleAccount>;
}

/// Where the callback sends the visitor, and which client it trusts.
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    client_id: Option<String>,
    signed_in_path: String,
    new_account_path: String,
}

impl GoogleConfig {
    /// `signed_in_path` is where a returning visitor lands (build it from
    /// the app's route, `Route::Home {}.to_string()`), `new_account_path`
    /// where a new account goes to finish its profile. The client id comes
    /// from `GOOGLE_OAUTH_CLIENT_ID`; see [`client_id`](Self::client_id).
    pub fn new(signed_in_path: impl Into<String>, new_account_path: impl Into<String>) -> Self {
        Self {
            client_id: None,
            signed_in_path: signed_in_path.into(),
            new_account_path: new_account_path.into(),
        }
    }

    /// Trust this web client id instead of reading `GOOGLE_OAUTH_CLIENT_ID`.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    fn resolved_client_id(&self) -> Option<String> {
        self.client_id
            .clone()
            .or_else(|| std::env::var("GOOGLE_OAUTH_CLIENT_ID").ok())
            .or_else(|| super::client_id().map(str::to_owned))
            .filter(|id| !id.trim().is_empty())
    }
}

struct Inner<C: Connection> {
    config: GoogleConfig,
    accounts: Box<dyn GoogleAccounts<C>>,
}

/// The route Google posts to. Merge it **before** the session, auth and guard
/// layers, which only wrap the routes registered ahead of them:
///
/// ```ignore
/// dioxus::server::router(App)
///     .merge(google_router::<AppUser, Client, _>(config, MyAccounts))
///     .layer(Extension(db))
///     .layer(from_fn_with_state(guard, require_session::<AppUser, Client>))
///     .layer(AuthSessionLayer::<AppUser, Client>::new(Some(db)))
///     .layer(SessionLayer::new(store))
/// ```
///
/// A browser is redirected to the signed-in (or new-account) path; a request
/// sending `Accept: application/json`, which is how the Android flow calls it,
/// gets a [`GoogleSignedIn`] instead.
pub fn google_router<U, C, A>(config: GoogleConfig, accounts: A) -> Router
where
    U: AuthUser,
    C: Connection,
    A: GoogleAccounts<C>,
{
    let inner = Arc::new(Inner::<C> {
        config,
        accounts: Box::new(accounts),
    });
    Router::new()
        .route(GOOGLE_CALLBACK_PATH, post(callback::<U, C>))
        .with_state(inner)
}

async fn callback<U, C>(
    State(inner): State<Arc<Inner<C>>>,
    context: SessionContext<U, C>,
    headers: HeaderMap,
    Form(params): Form<GoogleCallback>,
) -> Response
where
    U: AuthUser,
    C: Connection,
{
    let signed_in = match sign_in(&inner, &context, params.credential).await {
        Ok(signed_in) => signed_in,
        Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    };

    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("application/json"));
    if wants_json {
        Json(signed_in).into_response()
    } else {
        Redirect::to(&signed_in.destination).into_response()
    }
}

async fn sign_in<U, C>(
    inner: &Inner<C>,
    context: &SessionContext<U, C>,
    credential: String,
) -> Result<GoogleSignedIn, String>
where
    U: AuthUser,
    C: Connection,
{
    let client_id = inner
        .config
        .resolved_client_id()
        .ok_or("GOOGLE_OAUTH_CLIENT_ID is not configured.")?;
    // Checks the signature, issuer, audience and expiry. The audience is why
    // the web client id must be the one the token was issued for.
    let payload = google_oauth::AsyncClient::new(client_id)
        .validate_id_token(credential)
        .await
        .map_err(|error| error.to_string())?;

    let account = inner
        .accounts
        .find_or_create(
            &context.db,
            GoogleIdentity {
                subject: payload.sub,
                email: payload.email,
                email_verified: payload.email_verified.unwrap_or(false),
                name: payload.name,
                picture: payload.picture,
            },
        )
        .await
        .map_err(|error| error.to_string())?;

    context.auth_session.login_user(account.user_id);
    context.auth_session.remember_user(true);

    let destination = if account.is_new {
        inner.config.new_account_path.clone()
    } else {
        inner.config.signed_in_path.clone()
    };
    Ok(GoogleSignedIn {
        destination,
        is_new: account.is_new,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_callback_is_public_because_it_is_how_a_visitor_signs_in() {
        assert!(crate::is_public_endpoint(GOOGLE_CALLBACK_PATH));
        assert!(!crate::is_public_endpoint(
            "/api/v1/google_signin_callback/extra"
        ));
    }

    #[test]
    fn an_explicit_client_id_wins_and_a_blank_one_is_unset() {
        let config = GoogleConfig::new("/home", "/welcome").client_id("web-client");
        assert_eq!(config.resolved_client_id().as_deref(), Some("web-client"));
        let blank = GoogleConfig::new("/home", "/welcome").client_id("  ");
        // Falls through to the environment, which this test does not set.
        if std::env::var("GOOGLE_OAUTH_CLIENT_ID").is_err() && super::super::client_id().is_none() {
            assert_eq!(blank.resolved_client_id(), None);
        }
    }
}
