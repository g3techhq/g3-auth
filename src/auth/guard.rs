use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use surrealdb::Connection;

use super::{AuthSession, AuthUser, is_public_endpoint};

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
pub fn is_static_asset(path: &str) -> bool {
    path.starts_with("/wasm/") || path.starts_with("/assets/") || path == "/favicon.ico"
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

/// What the guard lets through without a session, beyond static assets and
/// [`public`](crate::public) server functions.
#[derive(Clone, Copy, Debug)]
pub struct AuthGuard {
    /// Where a signed-out page load is sent. It must itself be a public
    /// page, or the redirect loops.
    pub splash: &'static str,
    /// The pages that render without a session: the splash, sign-in, legal
    /// pages an app store links to, share links.
    ///
    /// Match paths, and be careful with `path.parse::<Route>()`: a
    /// catch-all `#[redirect("/:..segments", ..)]` parses **every** path,
    /// including every `/api/` one, as its target. A check like "parses as
    /// the splash route" then opens the whole app.
    pub public_page: fn(&str) -> bool,
}

impl AuthGuard {
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
/// const GUARD: AuthGuard = AuthGuard { splash: "/", public_page: is_public_page };
///
/// router
///     .layer(from_fn_with_state(GUARD, require_session::<AppUser, Client>))
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
        unauthenticated_response(&request, guard.splash)
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
        let guard = AuthGuard {
            splash: "/",
            public_page: is_public_page,
        };

        assert!(guard.allows_signed_out("/"));
        assert!(guard.allows_signed_out("/signin"));
        assert!(guard.allows_signed_out("/wasm/app_bg.wasm"));
        assert!(guard.allows_signed_out("/assets/logo.svg"));
        assert!(guard.allows_signed_out("/favicon.ico"));
        assert!(!guard.allows_signed_out("/profile"));
        assert!(!guard.allows_signed_out("/api/v1/get_bookmarks"));
    }
}
