use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use std::{fmt::Display, sync::Arc};

use surrealdb::Connection;

use super::{AuthSession, AuthUser, PublicRoutes, is_public_endpoint};

/// Shaped like dioxus-fullstack's own error payload, so the server function
/// client decodes it into a `ServerFnError::ServerError` carrying
/// `code: 401` rather than an opaque decode failure. A caller that wants to
/// react to an expired session has something unambiguous to match on.
pub const UNAUTHORIZED_BODY: &str =
    r#"{"message":"Your session has expired. Please sign in again.","code":401}"#;

/// Whether this request is a browser navigation, as opposed to a `fetch`.
///
/// Only a navigation can act on a redirect. `fetch` follows one
/// transparently, so a server function redirected to the sign-in page gets
/// that page's HTML back under a 200 where it expected JSON, which reaches
/// the app as a decode error indistinguishable from a real failure. That is
/// what strands a client whose session stopped resolving: every screen's
/// fetch quietly fails, and nothing sends the user back to sign in.
pub fn is_document_navigation(request: &Request) -> bool {
    // Every browser supporting Fetch Metadata sends `document` on a real
    // navigation and `empty` on a `fetch`, which settles it on its own.
    if let Some(destination) = request
        .headers()
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok())
    {
        return destination == "document";
    }

    // Without it, go by what was asked for: server functions live under
    // `/api/`, and everything else is a page. A client that sends no Fetch
    // Metadata at all (curl, a probe, an old browser) gets the redirect.
    !request.uri().path().starts_with("/api/")
}

/// Files every visitor needs before the app can decide anything: the WASM
/// bundle, bundled assets, and the favicon a browser fetches on its own.
/// Guarding the favicon would also write a session row per signed-out page
/// load.
///
/// Also `/.well-known/`: its files (Android asset links, Apple's app site
/// association, `security.txt`, ACME challenges) exist for clients that never
/// have a session, and usually come from a library rather than a function
/// the app could mark `#[public]`.
pub fn is_static_asset(path: &str) -> bool {
    path.starts_with("/wasm/")
        || path.starts_with("/assets/")
        || path.starts_with("/.well-known/")
        || path == "/favicon.ico"
}

/// What a signed-out request gets: a redirect to `splash` for a page load,
/// and a `401` with [`UNAUTHORIZED_BODY`] for anything else.
pub fn unauthenticated_response(request: &Request, splash: &str) -> Response {
    if is_document_navigation(request) {
        return Redirect::to(splash).into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        UNAUTHORIZED_BODY,
    )
        .into_response()
}

/// What the guard lets through without a session: static assets,
/// [`public`](crate::public) server functions, and the app's public pages.
#[derive(Clone, Debug)]
pub struct AuthGuard {
    splash: Arc<str>,
    public_page: fn(&str) -> bool,
}

impl AuthGuard {
    /// A guard whose public pages are the `#[public]` variants of a
    /// [`PublicRoutes`] enum, sending signed-out page loads to `splash`:
    ///
    /// ```ignore
    /// let guard = AuthGuard::for_routes(Route::Splash {});
    /// ```
    ///
    /// # Panics
    ///
    /// If `splash` is not marked `#[public]`: every signed-out page load
    /// would redirect to a page that redirects again.
    pub fn for_routes<R: PublicRoutes + Display>(splash: R) -> Self {
        Self::new(splash.to_string(), R::is_public_path)
    }

    /// A guard with public pages decided by `public_page`, for an app
    /// without a [`PublicRoutes`] enum. Prefer [`for_routes`](Self::for_routes).
    ///
    /// Match paths, and never with `path.parse::<Route>()`: a catch-all
    /// `#[redirect("/:..segments", ..)]` parses **every** path, including
    /// every `/api/` one, as its target, so a check on the parsed value
    /// opens the whole app.
    ///
    /// # Panics
    ///
    /// If `public_page` doesn't allow `splash`, for the same reason as
    /// [`for_routes`](Self::for_routes).
    pub fn new(splash: impl Into<String>, public_page: fn(&str) -> bool) -> Self {
        let splash: Arc<str> = splash.into().into();
        let guard = Self {
            splash,
            public_page,
        };
        assert!(
            guard.allows_signed_out(guard.splash_path()),
            "the splash `{}` must be a public page: the guard sends every signed-out page load \
             there, so guarding it makes that redirect loop forever. Mark it `#[public]`.",
            guard.splash,
        );
        guard
    }

    /// Where a signed-out page load is sent.
    pub fn splash(&self) -> &str {
        &self.splash
    }

    fn splash_path(&self) -> &str {
        self.splash.split(['?', '#']).next().unwrap_or_default()
    }

    /// Whether a request for `path` may proceed without a session.
    pub fn allows_signed_out(&self, path: &str) -> bool {
        is_static_asset(path) || (self.public_page)(path) || is_public_endpoint(path)
    }
}

/// Middleware denying every request without a signed-in user, except what
/// [`AuthGuard::allows_signed_out`] names.
///
/// Install it inside the auth session layer, so the session is resolved
/// first:
///
/// ```ignore
/// let guard = AuthGuard::for_routes(Route::Splash {});
///
/// router
///     .layer(from_fn_with_state(guard, require_session::<AppUser, Client>))
///     .layer(AuthSessionLayer::<AppUser, Client>::new(Some(db)).with_config(auth_config))
///     .layer(SessionLayer::new(session_store))
/// ```
///
/// It never signs anyone out. It runs on every request, and rotating the
/// session from a read path lets one unlucky request invalidate a session
/// other in-flight requests are still using; `sign_out` is where that
/// belongs.
pub async fn require_session<U: AuthUser, C: Connection>(
    State(guard): State<AuthGuard>,
    request: Request,
    next: Next,
) -> Response {
    if guard.allows_signed_out(request.uri().path()) {
        return next.run(request).await;
    }

    let is_authenticated = request
        .extensions()
        .get::<AuthSession<U, C>>()
        .is_some_and(AuthSession::is_authenticated);

    if is_authenticated {
        next.run(request).await
    } else {
        unauthenticated_response(&request, guard.splash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request_with(path: &str, headers: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder().uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).expect("valid test request")
    }

    #[test]
    fn browser_navigations_are_documents() {
        assert!(is_document_navigation(&request_with(
            "/profile",
            &[("sec-fetch-dest", "document"), ("accept", "text/html")]
        )));
    }

    #[test]
    fn server_function_calls_are_not_documents() {
        // Fetch Metadata settles it even when the other headers would read
        // as a navigation.
        assert!(!is_document_navigation(&request_with(
            "/api/v1/get_bookmarks",
            &[("sec-fetch-dest", "empty"), ("accept", "text/html")]
        )));
    }

    #[test]
    fn falls_back_to_the_path_without_fetch_metadata() {
        assert!(!is_document_navigation(&request_with(
            "/api/v1/get_bookmarks",
            &[]
        )));
        assert!(is_document_navigation(&request_with("/", &[])));
        assert!(is_document_navigation(&request_with("/profile", &[])));
    }

    #[test]
    fn signed_out_responses() {
        let page = unauthenticated_response(&request_with("/profile", &[]), "/");
        assert!(page.status().is_redirection());
        assert_eq!(page.headers()[header::LOCATION], "/");

        let fetch = unauthenticated_response(&request_with("/api/v1/x", &[]), "/");
        assert_eq!(fetch.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(fetch.headers()[header::CONTENT_TYPE], "application/json");
    }

    #[test]
    fn the_guard_lets_through_assets_and_named_pages_only() {
        fn is_public_page(path: &str) -> bool {
            matches!(path, "/" | "/signin")
        }
        let guard = AuthGuard::new("/", is_public_page);

        assert!(guard.allows_signed_out("/"));
        assert!(guard.allows_signed_out("/signin"));
        assert!(guard.allows_signed_out("/wasm/app_bg.wasm"));
        assert!(guard.allows_signed_out("/assets/logo.svg"));
        assert!(guard.allows_signed_out("/favicon.ico"));
        assert!(guard.allows_signed_out("/.well-known/assetlinks.json"));
        assert!(guard.allows_signed_out("/.well-known/apple-app-site-association"));
        assert!(!guard.allows_signed_out("/well-known/assetlinks.json"));
        assert!(!guard.allows_signed_out("/profile"));
        assert!(!guard.allows_signed_out("/api/v1/get_bookmarks"));
    }

    #[test]
    #[should_panic(expected = "must be a public page")]
    fn a_guarded_splash_is_refused() {
        fn only_signin(path: &str) -> bool {
            path == "/signin"
        }
        AuthGuard::new("/", only_signin);
    }
}
