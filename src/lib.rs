//! The shared core of g3 stack apps: the infrastructure every Dioxus
//! fullstack app on the stack needs, written once, behind feature flags.
//!
//! | Area | Feature | What it gives you |
//! |---|---|---|
//! | [Caching](cache) | `cache` | [`use_cached`] on the device, [`cache_shared`] on the server and CDN, [`invalidate_cached`] |
//! | [Auth](auth) | `auth` | Sessions in SurrealDB, the signed-in user on every request, a deny-by-default guard, and `#[public]` for the pages and server functions a signed-out visitor may use |
//!
//! # Setup
//!
//! Turn on the areas the app uses on the dependency itself, and each
//! platform feature in the app's feature of the same name:
//!
//! ```toml
//! [dependencies]
//! g3-kit = { version = "0.1", features = ["cache", "auth"] }
//!
//! [features]
//! web = ["dioxus/web", "g3-kit/web"]
//! mobile = ["dioxus/mobile", "g3-kit/mobile"]
//! server = ["dioxus/server", "g3-kit/server"]
//! ```
//!
//! # Features
//!
//! Areas (which code compiles):
//!
//! - `cache`: the [`cache`] module, re-exported at the crate root.
//! - `auth`: the [`auth`] module and [`public`].
//!
//! Platforms (which build this is):
//!
//! - `web`: the client cache persists to IndexedDB.
//! - `mobile`: the client cache persists to a redb file.
//! - `server`: the server halves of every area, and the dependencies they
//!   need (axum, axum_session, SurrealDB, moka). Turns the client cache off.

#![warn(missing_docs)]

#[cfg(feature = "cache")]
pub mod cache;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "cache")]
pub use cache::{
    CacheConfig, CacheKey, CacheOptions, CacheableFn, Cached, cache_shared, invalidate_all_cached,
    invalidate_cached, invalidate_cached_call, invalidate_cached_key, invalidate_cached_name,
    set_cache_owner, use_cached, use_cached_key, use_cached_key_with, use_cached_with,
    use_client_cache,
};
#[cfg(all(feature = "cache", feature = "server"))]
pub use cache::{ServerCache, cdn_cache_guard};

#[cfg(feature = "auth")]
pub use g3_kit_macros::public;

/// Support for the code the macros generate. Not public API.
#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "cache")]
    pub use crate::cache::__private::*;

    #[cfg(all(feature = "auth", feature = "server"))]
    pub use inventory;

    /// Registers a [`public`](crate::public) path; nothing outside a server
    /// build, where there is no guard to consult.
    #[cfg(feature = "auth")]
    pub use crate::__g3_kit_public_endpoint as public_endpoint;
}

#[doc(hidden)]
#[macro_export]
#[cfg(all(feature = "auth", feature = "server"))]
macro_rules! __g3_kit_public_endpoint {
    ($path:literal) => {
        const _: () = {
            $crate::__private::inventory::submit! {
                $crate::auth::PublicEndpoint::new($path)
            }
        };
    };
}

#[doc(hidden)]
#[macro_export]
#[cfg(all(feature = "auth", not(feature = "server")))]
macro_rules! __g3_kit_public_endpoint {
    ($path:literal) => {};
}
