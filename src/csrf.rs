//! Login-CSRF protection for the social sign-in callbacks.
//!
//! [`google::google_router`](crate::google::google_router) and
//! [`apple::apple_router`](crate::apple::apple_router) apply it themselves;
//! it is public for an app's own cross-site callback.
//!
//! Both providers post a signed token from a cross-site page, so the session
//! cookie (SameSite=Lax) cannot tie the post to the browser that started it.
//! Instead a cookie and a form field carry the same value (double submit), as
//! Google's own docs require for `g_csrf_token`; Apple's flow uses the `state`
//! the page stored in a cookie before leaving. An attacker who tricks a victim
//! into posting the attacker's token cannot make the victim's browser hold a
//! cookie with that value.
//!
//! Browsers always send `Origin` on a cross-origin POST. A request without one
//! is a native app's HTTP client, which no web page can impersonate, and has
//! no cookie jar to double-submit with.

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

const MAX_BODY: usize = 64 * 1024;

/// Which cookie must equal which form field.
#[derive(Clone, Copy, Debug)]
pub struct DoubleSubmit {
    /// The cookie name.
    pub cookie: &'static str,
    /// The `application/x-www-form-urlencoded` field that must equal it.
    pub field: &'static str,
}

impl DoubleSubmit {
    /// Google's own: the `g_csrf_token` cookie and form field it sends together.
    pub const GOOGLE: DoubleSubmit = DoubleSubmit {
        cookie: "g_csrf_token",
        field: "g_csrf_token",
    };

    /// The Apple button's: the `apple_state` cookie it sets, against `state`.
    pub const APPLE: DoubleSubmit = DoubleSubmit {
        cookie: "apple_state",
        field: "state",
    };

    /// Whether a request may proceed, for a callback that is a server function
    /// (which a layer cannot wrap): `headers` are the request's and `field` is
    /// the form field's value. Same rule as [`protect`].
    pub fn verify(self, headers: &axum::http::HeaderMap, field: Option<&str>) -> bool {
        let cookie = headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|header| cookie_value(header, self.cookie));
        allowed(headers.contains_key(header::ORIGIN), cookie, field)
    }
}

/// Wraps `router` so a browser POST must double-submit.
pub fn protect<S>(router: axum::Router<S>, rule: DoubleSubmit) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::middleware::from_fn_with_state(rule, double_submit))
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn form_value(body: &[u8], name: &str) -> Option<String> {
    url::form_urlencoded::parse(body)
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Whether a request may proceed. `from_browser` is "carries an Origin header".
fn allowed(from_browser: bool, cookie: Option<&str>, field: Option<&str>) -> bool {
    if !from_browser {
        return true;
    }
    matches!((cookie, field), (Some(cookie), Some(field)) if !cookie.is_empty() && cookie == field)
}

/// The middleware itself, for `axum::middleware::from_fn_with_state`.
pub async fn double_submit(
    State(rule): State<DoubleSubmit>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let cookie = parts
        .headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| cookie_value(header, rule.cookie));
    let field = form_value(&bytes, rule.field);
    if !allowed(
        parts.headers.contains_key(header::ORIGIN),
        cookie,
        field.as_deref(),
    ) {
        return (
            StatusCode::BAD_REQUEST,
            "Failed to verify the sign-in request.",
        )
            .into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_post_needs_matching_cookie_and_field() {
        assert!(allowed(true, Some("abc"), Some("abc")));
        assert!(!allowed(true, Some("abc"), Some("abx")));
        assert!(!allowed(true, None, Some("abc")));
        assert!(!allowed(true, Some("abc"), None));
        assert!(!allowed(true, Some(""), Some("")));
    }

    #[test]
    fn verify_applies_the_same_rule_to_a_server_function() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut browser = HeaderMap::new();
        browser.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://accounts.example.com"),
        );
        assert!(!DoubleSubmit::GOOGLE.verify(&browser, Some("t")));
        browser.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; g_csrf_token=t"),
        );
        assert!(DoubleSubmit::GOOGLE.verify(&browser, Some("t")));
        assert!(!DoubleSubmit::GOOGLE.verify(&browser, Some("other")));
        assert!(!DoubleSubmit::GOOGLE.verify(&browser, None));
        // Another provider's cookie does not count.
        assert!(!DoubleSubmit::APPLE.verify(&browser, Some("t")));
        assert!(
            DoubleSubmit::GOOGLE.verify(&HeaderMap::new(), None),
            "native: no Origin"
        );
    }

    #[test]
    fn a_native_client_without_an_origin_is_allowed() {
        assert!(allowed(false, None, None));
    }

    #[test]
    fn parses_cookies_and_form_fields() {
        assert_eq!(
            cookie_value("a=1; g_csrf_token=xyz; b=2", "g_csrf_token"),
            Some("xyz")
        );
        assert_eq!(cookie_value("a=1", "g_csrf_token"), None);
        assert_eq!(
            form_value(b"credential=t&g_csrf_token=x%2By", "g_csrf_token").as_deref(),
            Some("x+y")
        );
    }

    async fn post(origin: bool, cookie: Option<&str>, body: &str) -> StatusCode {
        use axum::{http::Method, routing::post as route};
        use tower::ServiceExt;

        let app = protect(
            axum::Router::new().route("/cb", route(|| async { "ok" })),
            DoubleSubmit {
                cookie: "t",
                field: "t",
            },
        );
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/cb")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if origin {
            request = request.header(header::ORIGIN, "https://accounts.example.com");
        }
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        app.oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn the_layer_blocks_a_forged_browser_post_and_passes_the_real_ones() {
        // A page posting its own token: the victim has no matching cookie.
        assert_eq!(
            post(true, None, "t=attacker").await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(true, Some("t=victim"), "t=attacker").await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(post(true, None, "").await, StatusCode::BAD_REQUEST);
        // The provider's own post, and a native app's.
        assert_eq!(
            post(true, Some("x=1; t=same"), "t=same&credential=c").await,
            StatusCode::OK
        );
        assert_eq!(post(false, None, "credential=c").await, StatusCode::OK);
    }
}
