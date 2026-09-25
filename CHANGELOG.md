# Changelog

All notable changes to `g3-kit` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-25

### Added

- `cache` feature, the caching library formerly developed as `g3-cache`
  (never published under that name):
  - Client cache: `use_cached` (a server function and its arguments) and
    `use_cached_key` (a named key), answered from memory, then a persistent
    store (IndexedDB on web, redb on mobile), then the server.
  - `invalidate_cached`, `invalidate_cached_call`, `invalidate_cached_key`,
    `invalidate_cached_name` and `invalidate_all_cached`; refetching on app
    focus; `set_cache_owner`, which empties the cache when the signed-in user
    changes and gates persistence until called.
  - `#[cache_shared(cdn = .., server = ..)]` for server functions whose
    answer is the same for every visitor, refusing non-`GET` routes,
    session-like extractors and `FullstackContext` reads at compile time.
  - `ServerCache`, a `const`-constructible in-process cache for `static`s,
    and a `moka` re-export.
  - `cdn::cdn_cache_for` and `cdn_cache_guard`: standard `Cache-Control`
    headers for any CDN, with session cookies stripped from shared responses
    and `private, no-cache` on every other API response.
- `auth` feature, consolidated from the g3 apps:
  - `SurrealSessionPool`, an `axum_session` store on SurrealDB 3, and
    `SESSIONS_SCHEMA` for its table. Its `count` now works on SurrealDB 3
    (the apps' copies failed to decode it).
  - `AuthUser`, `SessionUser` (anonymous by default), `SessionContext`, and
    the `AuthSession`/`AuthSessionLayer` aliases.
  - `require_session` with `AuthGuard`: deny by default, a `401` JSON body
    for server function calls and a redirect only for page loads.
  - `#[public]` to mark a server function reachable without a session, with
    `is_public_endpoint` and `public_endpoints`.
  - `#[derive(PublicRoutes)]` with `#[public]` on a `Routable` enum's pages,
    matched against the routes' own `#[route]`/`#[nest]` patterns rather than
    by parsing the path, so a catch-all `#[redirect]` can't open anything.
  - `AuthGuard::for_routes`, which refuses a splash that isn't public.
