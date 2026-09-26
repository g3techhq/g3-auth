# g3-auth

[![CI](https://github.com/g3techhq/g3-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/g3techhq/g3-auth/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/g3-auth.svg)](https://crates.io/crates/g3-auth)
[![docs.rs](https://docs.rs/g3-auth/badge.svg)](https://docs.rs/g3-auth)
[![License](https://img.shields.io/crates/l/g3-auth.svg)](#license)

Session auth for Dioxus fullstack apps on SurrealDB, part of the g3 stack:
sessions stored in the database, the signed-in user on every request, and
a guard that denies by default.

## Setup

```toml
[dependencies]
g3-auth = "0.1"

[features]
server = ["dioxus/server", "g3-auth/server"]
```

Only `server` pulls in the server side (axum, axum_session, SurrealDB).
Without it, `#[public]` and `PublicRoutes` still compile, so the same code
builds for web and mobile.

## Usage


Every request needs a signed-in user unless it is for a static asset, or a
page or server function marked `#[public]`:

```rust
/// The splash asks this before it knows whether anyone is signed in.
#[g3_auth::public]
#[get("/api/v1/is_signed_in", ctx: SessionContext)]
pub async fn is_signed_in() -> Result<bool> {
    Ok(!ctx.session_user.anonymous)
}
```

Pages are marked on the route enum, next to `#[route]`:

```rust
#[derive(Clone, Routable, PartialEq, PublicRoutes)]
enum Route {
    #[redirect("/:..segments", |segments: Vec<String>| Route::Splash {})]
    #[public]
    #[route("/")]
    Splash {},
    #[nest("/games/:game_id")]
        #[public]
        #[route("/join")]
        JoinGame { game_id: String },
    #[end_nest]
    #[route("/home")]
    Home {},
}
```

Forgetting `#[public]` is the safe mistake: a signed-out caller gets a `401`
JSON body the client can decode, and a signed-out page load is redirected
to the splash. Opening an endpoint up is one reviewable line next to the
function or page, not an edit to a list somewhere else.
`g3_auth::public_endpoints()` and `Route::PUBLIC_PATTERNS` list them all, for
pinning in a test.

Setup, innermost layer first:

```rust
use g3_auth::{AuthGuard, AuthSessionLayer, AuthUser, PublicRoutes, require_session};

pub enum AppUser {}
impl AuthUser for AppUser {} // table `user`, name field `display_name`

pub type SessionContext = g3_auth::SessionContext<AppUser, Client>;

// Panics at startup if the splash isn't `#[public]`: the redirect would loop.
let guard = AuthGuard::for_routes(Route::Splash {});

dioxus::server::router(App)
    .layer(Extension(Arc::clone(&db)))
    .layer(from_fn_with_state(guard, require_session::<AppUser, Client>))
    .layer(AuthSessionLayer::<AppUser, Client>::new(Some(Arc::clone(&db))))
    .layer(SessionLayer::new(session_store))
```

Sessions live in SurrealDB through `SurrealSessionPool`; load
`g3_auth::SESSIONS_SCHEMA` for its table. Mark the session cookie `Secure` in
production: `SessionConfig::default().with_secure(!cfg!(debug_assertions))`.

The derive matches request paths against the marked routes' own patterns and
never parses a path into the enum: a catch-all
`#[redirect("/:..segments", ..)]` parses *every* path, including every `/api/`
one, as its target, so "parses as the splash" would open the whole app. For
the same reason it refuses `#[public]` on a top-level catch-all route.

A server function called during server-side rendering runs without any
middleware, so the guard covers HTTP requests only. Functions acting on
"the current user" should still check `session_user.anonymous`.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
