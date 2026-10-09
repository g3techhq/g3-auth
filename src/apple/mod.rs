//! "Sign in with Apple", all batteries included: a button for the web and iOS
//! and the endpoints behind it.
//!
//! ```ignore
//! // Anywhere in a screen:
//! AppleSignIn {}
//! ```
//!
//! ```ignore
//! // Once, in `main`, before the layers (so the session wraps it):
//! let router = dioxus::server::router(App)
//!     .merge(g3_auth::apple::apple_router::<AppUser, Client, _>(
//!         AppleConfig::new("/home", "/signin/settings"),
//!         MyAccounts,
//!     ))
//!     .layer(..);
//! ```
//!
//! Load [`APPLE_SCHEMA`](crate::APPLE_SCHEMA) with the sessions schema: it holds
//! the one-time challenge each attempt starts with.
//!
//! # How a sign-in is checked
//!
//! 1. The button asks [`APPLE_PREPARE_PATH`] for a single-use `state` and
//!    `nonce`, kept in the database for ten minutes. The web page also stores
//!    the `state` in an `apple_state` cookie before it leaves.
//! 2. Apple posts the result to [`APPLE_CALLBACK_PATH`] from its own page. The
//!    session cookie is `SameSite=Lax` and so is not sent, which means nothing
//!    but that cookie and the `state` can tie the post to the browser that
//!    started it: [`csrf`](crate::csrf) rejects a browser post whose cookie
//!    and `state` differ.
//! 3. The challenge is consumed (a replay finds nothing), and the identity token
//!    is verified against Apple's keys: signature, issuer, audience, expiry and
//!    the challenge's nonce. With a signing key configured the authorization
//!    code is exchanged with Apple too, and the token it returns is the one
//!    that counts.
//!
//! # Configuration
//!
//! | Variable | |
//! | --- | --- |
//! | `APPLE_SERVICES_ID` | The web Services ID. Required, at build time for the button and at run time for the server. |
//! | `APP_ORIGIN` | The public origin Apple returns to; its return URL is `<origin>/api/v1/apple_signin_callback`. |
//! | `APPLE_BUNDLE_ID` | The iOS app's bundle id, the audience of native tokens (or [`AppleConfig::native_client_id`]). |
//! | `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY` or `APPLE_PRIVATE_KEY_PATH` | A Sign in with Apple key. Turns on the code exchange and [`revoke_token`], which App Store review requires when an account is deleted. |

mod component;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
mod tokens;

use serde::{Deserialize, Serialize};

pub use component::{AppleSignIn, AppleSignInProps};
#[cfg(feature = "server")]
pub use server::{
    AppleAccount, AppleAccounts, AppleConfig, AppleIdentity, apple_router, revoke_token,
};

/// Where the button asks for a challenge. Public: it runs before there is a
/// session.
pub const APPLE_PREPARE_PATH: &str = "/api/v1/apple_signin_prepare";

/// Where Apple, and the native flow, post the signed result. Public: the
/// request is how a visitor becomes signed in.
pub const APPLE_CALLBACK_PATH: &str = "/api/v1/apple_signin_callback";

/// What [`APPLE_PREPARE_PATH`] is asked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplePrepare {
    /// Whether the iOS sheet, not Apple's web page, will use the challenge.
    #[serde(default)]
    pub native: bool,
    /// Where the visitor was headed before signing in, handed back to
    /// [`AppleAccounts::destination`] when the attempt finishes. Opaque to
    /// g3-auth, and the client's word: validate it there.
    #[serde(default)]
    pub return_to: Option<String>,
}

/// The single-use challenge the button signs in with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleChallenge {
    /// The web Services ID (the `clientId` of Apple's script).
    pub services_id: String,
    /// The return URL registered with Apple; empty for a native sign-in.
    pub redirect_uri: String,
    /// Echoed back by Apple; also the value of the `apple_state` cookie.
    pub state: String,
    /// Echoed back inside the identity token.
    pub nonce: String,
}

/// What a native sign-in answers: where the server would have redirected the
/// browser. A web sign-in never sees this, the browser follows the redirect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleSignedIn {
    /// The path to show next: [`AppleConfig`]'s signed-in path, or its
    /// new-account path the first time.
    pub destination: String,
    /// Whether this sign-in created the account.
    pub is_new: bool,
}

/// The Apple Services ID, if one is configured. Compiled into the client
/// (`option_env!`, so it has to be in the environment of `dx build`, not just a
/// `.env` file) and read from the environment at run time on the server.
pub fn services_id() -> Option<&'static str> {
    const BUILT_IN: Option<&str> = option_env!("APPLE_SERVICES_ID");
    BUILT_IN.filter(|id| !id.trim().is_empty())
}
