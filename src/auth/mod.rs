//! Session auth for Dioxus fullstack apps on SurrealDB (the `auth`
//! feature): sessions stored in the database, a signed-in user on every
//! request, and a guard that denies by default.
//!
//! # The guard
//!
//! Every request needs a signed-in user unless it is for:
//!
//! - a static asset ([`is_static_asset`]),
//! - a page marked `#[public]` in the app's [`PublicRoutes`] enum, or
//! - a server function marked [`public`](crate::public):
//!
//! ```ignore
//! /// The splash asks this before it knows whether anyone is signed in.
//! #[g3_kit::public]
//! #[get("/api/v1/is_signed_in", ctx: SessionContext)]
//! pub async fn is_signed_in() -> Result<bool> {
//!     Ok(!ctx.session_user.anonymous)
//! }
//! ```
//!
//! Forgetting `#[public]` is the safe mistake: a signed-out caller gets a
//! `401`, which the page can see and act on. A signed-out page load is
//! redirected to the splash instead ([`is_document_navigation`]).
//!
//! Pages are marked the same way, on the route enum:
//!
//! ```ignore
//! #[derive(Clone, Routable, PartialEq, PublicRoutes)]
//! enum Route {
//!     #[redirect("/:..segments", |segments: Vec<String>| Route::Splash {})]
//!     #[public]
//!     #[route("/")]
//!     Splash {},
//!     #[nest("/games/:game_id")]
//!         #[public]
//!         #[route("/join")]
//!         JoinGame { game_id: String },
//!     #[end_nest]
//!     #[route("/home")]
//!     Home {},
//! }
//! ```
//!
//! # Setup
//!
//! ```toml
//! [dependencies]
//! g3-kit = { version = "0.1", features = ["auth"] }
//!
//! [features]
//! server = ["dioxus/server", "g3-kit/server"]
//! ```
//!
//! Load [`SESSIONS_SCHEMA`] into the database (or copy it into the app's
//! schema), describe the account table with [`AuthUser`], and build the
//! router, innermost layer first:
//!
//! ```ignore
//! pub enum AppUser {}
//! impl AuthUser for AppUser {}
//!
//! // Panics at startup if the splash isn't `#[public]`: the redirect would loop.
//! let guard = AuthGuard::for_routes(Route::Splash {});
//!
//! let session_store = SessionStore::new(
//!     Some(SurrealSessionPool::new(Arc::clone(&db))),
//!     SessionConfig::default().with_secure(!cfg!(debug_assertions)),
//! )
//! .await?;
//!
//! dioxus::server::router(App)
//!     .layer(Extension(Arc::clone(&db)))
//!     .layer(from_fn_with_state(guard, require_session::<AppUser, Client>))
//!     .layer(AuthSessionLayer::<AppUser, Client>::new(Some(Arc::clone(&db))))
//!     .layer(SessionLayer::new(session_store))
//! ```
//!
//! # What the guard does not cover
//!
//! A server function called during server-side rendering runs directly,
//! without any middleware, so the guard only applies to HTTP requests. A
//! public page that renders a private server function would run it for a
//! signed-out visitor. Functions that act on "the current user" should still
//! check `session_user.anonymous` rather than trust that they were guarded.

#[cfg(feature = "server")]
mod guard;
#[cfg(feature = "server")]
mod public;
mod routes;
#[cfg(feature = "server")]
mod session_store;
#[cfg(feature = "server")]
mod user;

#[cfg(feature = "server")]
pub use guard::{
    AuthGuard, UNAUTHORIZED_BODY, is_document_navigation, is_static_asset, require_session,
    unauthenticated_response,
};
#[cfg(feature = "server")]
pub use public::{PublicEndpoint, is_public_endpoint, public_endpoints};
pub use routes::PublicRoutes;
#[cfg(feature = "server")]
pub use session_store::SurrealSessionPool;
#[cfg(feature = "server")]
pub use user::{AuthSession, AuthSessionLayer, AuthUser, SessionContext, SessionUser};

/// The `sessions` table [`SurrealSessionPool`] reads and writes.
#[cfg(feature = "server")]
pub const SESSIONS_SCHEMA: &str = include_str!("sessions.surql");

#[cfg(all(test, feature = "server"))]
mod db_tests;
