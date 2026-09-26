# Changelog

All notable changes to `g3-auth` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-25

### Added

Consolidated from the g3 apps (media-mancer, greenside-partee, g3-stack),
and briefly published as part of the since-yanked `g3-kit`:

- `SurrealSessionPool`, an `axum_session` store on SurrealDB 3, and
  `SESSIONS_SCHEMA` for its table. Its `count` now works on SurrealDB 3 (the
  apps' copies failed to decode it).
- `AuthUser`, `SessionUser` (anonymous by default), `SessionContext`, and the
  `AuthSession`/`AuthSessionLayer` aliases.
- `require_session` with `AuthGuard`: deny by default, a `401` JSON body for
  server function calls and a redirect only for page loads.
- `#[public]` to mark a server function reachable without a session, with
  `is_public_endpoint` and `public_endpoints`.
- `#[derive(PublicRoutes)]` with `#[public]` on a `Routable` enum's pages,
  matched against the routes' own `#[route]`/`#[nest]` patterns rather than by
  parsing the path, so a catch-all `#[redirect]` can't open anything.
- `AuthGuard::for_routes`, which refuses a splash that isn't public.
