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

### Stay signed in on a phone

A native app's HTTP client forgets cookies when the process dies, so without
this every relaunch signs everyone out. Enable the feature for the platform and
call `init` first in `main` (it does nothing on the web and the server):

```toml
[features]
mobile = ["dioxus/mobile", "g3-auth/mobile"]   # or "g3-auth/desktop"
```

```rust
fn main() {
    g3_auth::init();
    dioxus::launch(App);
}
```

### Sign in with Google

```toml
g3-auth = { version = "0.1", features = ["google"] }

[features]
server = ["dioxus/server", "g3-auth/server"]
```

Put the button where it goes; it is Google's own button on the web and a
system account picker on Android:

```rust
GoogleSignIn { on_signed_in: move |signed_in: GoogleSignedIn| { /* native only */ } }
```

On the server, say how a Google identity becomes one of your accounts and
merge the callback before the session layers:

```rust
struct Accounts;

#[async_trait]
impl GoogleAccounts<Client> for Accounts {
    async fn find_or_create(&self, db: &Surreal<Client>, who: GoogleIdentity) -> anyhow::Result<GoogleAccount> {
        // look up by who.subject; create the row if there is none
        Ok(GoogleAccount { user_id, is_new })
    }
}

dioxus::server::router(App)
    .merge(google_router::<AppUser, Client, _>(
        GoogleConfig::new("/home", "/welcome"),
        Accounts,
    ))
    .layer(/* extension, guard, auth session, session store */)
```

The web client id is public and read from `GOOGLE_OAUTH_CLIENT_ID` at build
time by the client and at run time by the server. Android also needs an
Android OAuth client for the app's package and signing key in the same Google
Cloud project, or the system flow returns no token.

### The guard


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
