//! "Sign in with Google", all batteries included: a button for every
//! platform and the callback behind it.
//!
//! ```ignore
//! // Anywhere in a screen:
//! GoogleSignIn { on_signed_in: move |signed_in: GoogleSignedIn| { .. } }
//! ```
//!
//! ```ignore
//! // Once, in `main`, before the layers (so the session wraps it):
//! let router = dioxus::server::router(App)
//!     .merge(g3_auth::google::google_router::<AppUser, Client, _>(
//!         GoogleConfig::new("/home", "/signin/settings"),
//!         MyAccounts,
//!     ))
//!     .layer(..);
//! ```
//!
//! The client id is the **web** OAuth client's, public, and read from the
//! `GOOGLE_OAUTH_CLIENT_ID` environment variable: at build time by the
//! client (see [`client_id`]) and at run time by the server. Android needs an
//! Android OAuth client for the app's package and signing key in the same
//! Google Cloud project, or the system flow returns no token.

mod component;
#[cfg(feature = "server")]
mod server;

use serde::{Deserialize, Serialize};

pub use component::{GoogleSignIn, GoogleSignInProps};
#[cfg(feature = "server")]
pub use server::{GoogleAccount, GoogleAccounts, GoogleConfig, GoogleIdentity, google_router};

/// Where Google, and the Android flow, post the signed ID token. Public: the
/// guard lets it through because the request is how a visitor becomes
/// signed in.
pub const GOOGLE_CALLBACK_PATH: &str = "/api/v1/google_signin_callback";

/// The form body Google (and the native flow) posts to
/// [`GOOGLE_CALLBACK_PATH`].
#[derive(Serialize, Deserialize)]
pub struct GoogleCallback {
    /// The signed ID token.
    pub credential: String,
}

/// What a native sign-in answers: where the server would have redirected the
/// browser. A web sign-in never sees this, the browser follows the redirect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleSignedIn {
    /// The path to show next: [`GoogleConfig`]'s signed-in path, or its
    /// new-account path the first time.
    pub destination: String,
    /// Whether this sign-in created the account.
    pub is_new: bool,
}

/// The Google OAuth web client id, if one is configured. Compiled into the
/// client (`option_env!`, so it has to be in the environment of `dx build`,
/// not just a `.env` file), read from the environment at run time on the
/// server.
pub fn client_id() -> Option<&'static str> {
    const BUILT_IN: Option<&str> = option_env!("GOOGLE_OAUTH_CLIENT_ID");
    BUILT_IN.filter(|id| !id.trim().is_empty())
}
