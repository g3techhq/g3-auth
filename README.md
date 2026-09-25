# g3-core

[![CI](https://github.com/g3techhq/g3-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/g3techhq/g3-core/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/g3-core.svg)](https://crates.io/crates/g3-core)
[![docs.rs](https://docs.rs/g3-core/badge.svg)](https://docs.rs/g3-core)
[![License](https://img.shields.io/crates/l/g3-core.svg)](#license)

The shared core of g3 stack apps: the infrastructure every Dioxus fullstack
app on the stack needs, written once and fixed once, behind feature flags.

| Area | Feature | What it gives you |
|---|---|---|
| [Caching](#caching) | `cache` | `use_cached` on the device, `#[cache_shared]` on the server and CDN, `invalidate_cached` |
| [Auth](#auth) | `auth` | Sessions in SurrealDB, the signed-in user on every request, a deny-by-default guard, and `#[public]` for what a signed-out visitor may call |

## Setup

Turn on the areas the app uses on the dependency itself, and each platform
feature in the app's feature of the same name:

```toml
[dependencies]
g3-core = { version = "0.1", features = ["cache", "auth"] }

[features]
web = ["dioxus/web", "g3-core/web"]          # client cache persists to IndexedDB
mobile = ["dioxus/mobile", "g3-core/mobile"] # client cache persists to a redb file
server = ["dioxus/server", "g3-core/server"] # server halves of every area; client cache off
```

## Caching

```rust
use g3_core::{cache_shared, invalidate_cached, use_cached};

// A screen: show the last known answer at once, refetch in the background.
let media = use_cached(get_media, (id.clone(),));

// After a mutation: refetch what it changed.
save_rating(id.clone(), score).await?;
invalidate_cached(get_my_rating);

// A public read: cached at the CDN and on the server for 5 minutes.
#[cache_shared(cdn = 300, server = "5m")]
#[get("/api/trending?media_type", db: Db)]
pub async fn get_trending(media_type: Option<MediaType>) -> Result<Vec<Media>> { .. }
```

### Choosing a cache

| | Client | Server | CDN |
|---|---|---|---|
| **For** | Showing the last known data at once | Not repeating slow or rate-limited work | Answering identical public requests without the server |
| **Holds** | One user's data, on one device | Shared answers, in one process | Whole shared HTTP responses |
| **Refreshed by** | Screen opens, `invalidate_cached`, app focus | Expiry only | Expiry only |
| **API** | `use_cached`, `use_cached_key` | `#[cache_shared(server = ..)]`, `ServerCache` | `#[cache_shared(cdn = ..)]`, `cdn_cache_guard` |

**The rule:** data that depends on who is asking is cached on the client
only. Data that is the same for everyone may also be cached on the server
and at the CDN. `#[cache_shared]` refuses, at compile time, functions that
bind a session, auth, user or cookie extractor, and anything that isn't a
`GET`.

For caching part of a server function, declare a cache where it is used:

```rust
static DESCRIPTIONS: ServerCache<String, Option<Description>> =
    ServerCache::new(Duration::from_secs(60 * 60), 10_000);

DESCRIPTIONS.get_or_fetch(media_id, google_description(&media)).await
```

In the app:

```rust
use g3_core::{CacheConfig, set_cache_owner, use_client_cache};

fn App() -> Element {
    // Once, first thing in the root component.
    use_client_cache(CacheConfig::new("my-app"));
    // Whenever the signed-in user is known or changes, and on sign-out:
    // spawn(set_cache_owner(user_id));
    // ...
}
```

```rust
// Server router: once, outside the session layer.
.layer(session_layer)
.layer(g3_core::cdn_cache_guard("/api"))
```

Only standard `Cache-Control` headers are sent (`public`, `s-maxage`,
`private`, `no-cache`), so any CDN or shared cache works. Most won't cache
API responses until told to (in Cloudflare, a Cache Rule making the API
paths eligible); until then nothing is cached at the CDN, which is safe.

What you still have to handle:

- **Invalidate after mutations.** Only the mutation knows which reads it
  changed.
- **Write mutations as "set to", not "toggle".** A device showing stale
  state sends what it saw; a toggle then undoes another device's change.
- **Only share functions whose answer comes from their arguments.** The
  compile-time check catches session-like extractors, not every way a
  function can read the visitor.

## Auth

Every request needs a signed-in user unless it is for a static asset, a
page the app names, or a server function marked `#[public]`:

```rust
/// The splash asks this before it knows whether anyone is signed in.
#[g3_core::public]
#[get("/api/v1/is_signed_in", ctx: SessionContext)]
pub async fn is_signed_in() -> Result<bool> {
    Ok(!ctx.session_user.anonymous)
}
```

Forgetting `#[public]` is the safe mistake: a signed-out caller gets a `401`
JSON body the client can decode, and a signed-out page load is redirected
to the splash. Opening an endpoint up is one reviewable line next to the
function, not an edit to a list somewhere else. `auth::public_endpoints()`
lists them all, for pinning in a test.

Setup, innermost layer first:

```rust
use g3_core::auth::{AuthGuard, AuthSessionLayer, AuthUser, SurrealSessionPool, require_session};

pub enum AppUser {}
impl AuthUser for AppUser {} // table `user`, name field `display_name`

pub type SessionContext = g3_core::auth::SessionContext<AppUser, Client>;

fn is_public_page(path: &str) -> bool {
    matches!(path, "/" | "/signin" | "/privacy-policy")
}
const GUARD: AuthGuard = AuthGuard { splash: "/", public_page: is_public_page };

dioxus::server::router(App)
    .layer(Extension(Arc::clone(&db)))
    .layer(from_fn_with_state(GUARD, require_session::<AppUser, Client>))
    .layer(AuthSessionLayer::<AppUser, Client>::new(Some(Arc::clone(&db))))
    .layer(SessionLayer::new(session_store))
```

Sessions live in SurrealDB through `SurrealSessionPool`; load
`auth::SESSIONS_SCHEMA` for its table. Mark the session cookie `Secure` in
production: `SessionConfig::default().with_secure(!cfg!(debug_assertions))`.

Be careful naming public pages with `path.parse::<Route>()`: a catch-all
`#[redirect("/:..segments", ..)]` parses *every* path, including every
`/api/` one, as its target, so "parses as the splash" opens the whole app.

A server function called during server-side rendering runs without any
middleware, so the guard covers HTTP requests only. Functions acting on
"the current user" should still check `session_user.anonymous`.

## Test bed

`testbed/` is a small Dioxus app using the cache API against real server
functions. `just testbed` builds it for the server and the browser.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
