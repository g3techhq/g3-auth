# AGENTS.md

Instructions for coding agents working in this repository (Claude Code, Codex,
Cursor, Copilot, and anything else that reads `AGENTS.md`). Useful for people
too. Follow these over your defaults.

## What this is

**g3-auth** is session auth for Dioxus fullstack apps on SurrealDB: sessions
stored in the database, the signed-in user on every request, and a guard
that **denies by default**. A request passes without a session only when it
is a static asset or `/.well-known/` file, a page marked `#[public]` on the
app's `PublicRoutes` enum, or a server function marked `#[g3_auth::public]`.
Part of the g3 stack; media-mancer, greenside-partee, tawny and g3-stack sit
behind it.

| Piece | Version | Reference |
| --- | --- | --- |
| Dioxus (fullstack) | 0.7.9 | [dioxuslabs.com/learn/0.7](https://dioxuslabs.com/learn/0.7/) |
| axum + axum_session / axum_session_auth | 0.8 / 0.20 | the crate docs |
| SurrealDB | =3.2.4 | `src/sessions.surql` |
| Rust | edition 2024 | `rust-toolchain.toml` |

**Your training data does not know this crate.** The crate docs in
`src/lib.rs` and the README are the user-facing reference and must stay true.

## Map

```
src/lib.rs              Exports, and the crate docs (the guard, setup, layer order)
src/guard.rs            require_session: 401 for a fetch, redirect for a page load
src/public.rs           #[public] server-function registry
src/routes.rs           PublicRoutes: matching a path against the app's route patterns
src/session_store.rs    SurrealSessionPool: sessions in SurrealDB
src/sessions.surql      The session table schema apps load (SESSIONS_SCHEMA)
src/user.rs             AuthUser, SessionUser, the extractor
src/db_tests.rs         Store and user-loading tests on in-memory SurrealDB
macros/src/lib.rs       #[public] and #[derive(PublicRoutes)]
tests/                  Public endpoints and routes, end to end
CHANGELOG.md            Every user-visible change, under [Unreleased] until a release
```

## Commands

```bash
just check        # client, server, wasm32, and macros
just test         # nextest + doc tests (server feature), and macros
just lint-strict  # clippy with warnings as errors, server and wasm32
just pre-push     # format, check, lint, test, typos
```

## Definition of done

1. `just pre-push` passes.
2. A user-visible change has a line under `## [Unreleased]` in `CHANGELOG.md`.
3. Any change to what passes the guard has a test showing both what now
   passes and what still does not.
4. A guard or session change was exercised in a consuming app (sign in as a
   guest, load a guarded page signed out, call a guarded endpoint signed out)
   through a `[patch.crates-io]` path override removed afterwards.

If you could not do one of these, say which and why.

---

## Rules

### Security

- **Deny by default.** Nothing becomes public by omission, by a prefix match,
  or by a fallback. Forgetting `#[public]` must stay the safe mistake: a `401`
  a page can act on.
- **Never decide access by parsing a path into the app's `Route`.** A
  catch-all `#[redirect("/:..segments", ..)]` parses every path, `/api/`
  included, as its target. `PublicRoutes` matches the route *patterns*.
- A signed-out **fetch** gets a `401`; a signed-out **page load** is
  redirected to the splash (`is_document_navigation`, from `Sec-Fetch-Dest`,
  or the `/api/` prefix without it). A redirect served to a fetch comes back
  as HTML the caller cannot decode.
- The extractor's rejection is never `()`: axum renders `()` as an empty
  `200`, which the client decodes as "nobody is signed in". A misconfigured
  layer stack must look like the server fault it is.
- **Server functions called during SSR run without middleware.** Document
  that functions acting for the current user still check
  `session_user.anonymous`.
- Bind every value into SurrealQL; never `format!` one in.

### Compatibility

- Without the `server` feature, `#[public]` and `PublicRoutes` still compile,
  so an app's shared code builds for web and mobile. Keep server-only types
  behind the feature.
- Layer order in the docs (session store innermost) is load-bearing; change it
  only with the docs and the apps' `main.rs` in the same breath.

### Releases

- Releases publish from `publish-crates.yml` (crates.io trusted publishing).
  Do not run `cargo publish` by hand, and do not release without the
  maintainer's go-ahead.
- Commits follow Conventional Commits; lefthook checks them.

## Where to look

- `src/lib.rs` crate docs: the guard, setup, and layer order
- `README.md` and `CHANGELOG.md`
- g3-stack's `docs/authentication.md`, for how an app wires it up
