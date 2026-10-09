//! Rate limits for the endpoints where volume is itself the abuse: signing in,
//! creating accounts, redeeming codes.
//!
//! ```ignore
//! let limits = RateLimits::new()
//!     // Names the address header per deployment (see below); unset, limits key on the session.
//!     .client_ip_header_from_env("CLIENT_IP_HEADER")
//!     .limit(Limit::per_hour(&["/api/v1/sign_up_email", "/api/v1/sign_in_guest"], KeyBy::ClientIp, 10))
//!     .limit(Limit::per_hour(&["/api/v1/sign_in_email"], KeyBy::ClientIp, 30));
//!
//! let router = limits.apply(router);
//! ```
//!
//! # What a limit keys on
//!
//! - [`KeyBy::Session`] is the `session` cookie `axum_session` sets on every
//!   visitor. A new session is a fresh bucket, so this limits a browser, not an
//!   attacker, who just drops the cookie.
//! - [`KeyBy::ClientIp`] is a header naming the visitor's address. It is only as
//!   trustworthy as whatever sets it: a header like `cf-connecting-ip` is safe
//!   only when nobody but the proxy that sets it can reach the app, since
//!   otherwise a client sends its own. With no header configured, or none on the
//!   request (local development), it falls back to the session.
//!
//! The IP is not read from the connection because Dioxus's server loop does not
//! attach `ConnectInfo`, so `tower_governor`'s peer-address extractors never find
//! a key.
//!
//! A limit is answered with a `429` shaped like Dioxus's own error payload
//! (`{"message", "code"}`) and a `Retry-After`, so the client reads it as a server
//! function error and shows the message as written.

use std::{num::NonZeroU32, sync::Arc};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter, clock::Clock};

/// The cookie `axum_session` keeps the visitor's session in.
const SESSION_COOKIE: &str = "session";

/// Keys are kept per visitor; past this many, stale ones are dropped so a flood
/// of one-off keys cannot grow memory without bound.
const MAX_TRACKED_KEYS: usize = 50_000;

/// What a [`Limit`] counts requests by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBy {
    /// The visitor's session cookie.
    Session,
    /// The visitor's address, from [`RateLimits::client_ip_header`].
    ClientIp,
}

/// One limit: some paths, a key, and a quota.
pub struct Limit {
    paths: &'static [&'static str],
    key_by: KeyBy,
    limiter: DefaultKeyedRateLimiter<String>,
}

impl Limit {
    /// At most `count` requests an hour to `paths` for each key, in a burst or
    /// spread out.
    ///
    /// # Panics
    ///
    /// If `count` is zero.
    pub fn per_hour(paths: &'static [&'static str], key_by: KeyBy, count: u32) -> Self {
        Self::new(paths, key_by, Quota::per_hour(non_zero(count)))
    }

    /// At most `count` requests a minute to `paths` for each key.
    ///
    /// # Panics
    ///
    /// If `count` is zero.
    pub fn per_minute(paths: &'static [&'static str], key_by: KeyBy, count: u32) -> Self {
        Self::new(paths, key_by, Quota::per_minute(non_zero(count)))
    }

    fn new(paths: &'static [&'static str], key_by: KeyBy, quota: Quota) -> Self {
        Self {
            paths,
            key_by,
            limiter: RateLimiter::keyed(quota),
        }
    }
}

fn non_zero(count: u32) -> NonZeroU32 {
    NonZeroU32::new(count).expect("a rate limit must allow at least one request")
}

/// A set of [`Limit`]s, applied as one layer.
#[derive(Default)]
pub struct RateLimits {
    limits: Vec<Limit>,
    client_ip_header: Option<String>,
}

impl RateLimits {
    /// No limits yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The request header that carries the visitor's address, such as
    /// `cf-connecting-ip`. Only name one that nobody but your proxy can set.
    #[must_use]
    pub fn client_ip_header(mut self, name: impl Into<String>) -> Self {
        self.client_ip_header = Some(name.into());
        self
    }

    /// The same, read from the environment variable `var` (empty or unset means
    /// none). Whether a header can be trusted is a fact about the deployment, not
    /// the code, so a deployment names it: `CLIENT_IP_HEADER=cf-connecting-ip` when
    /// only Cloudflare can reach the app.
    #[must_use]
    pub fn client_ip_header_from_env(self, var: &str) -> Self {
        match std::env::var(var)
            .ok()
            .map(|value| value.trim().to_string())
        {
            Some(name) if !name.is_empty() => self.client_ip_header(name),
            _ => self,
        }
    }

    /// Adds a limit. A path in two limits is counted against both.
    #[must_use]
    pub fn limit(mut self, limit: Limit) -> Self {
        self.limits.push(limit);
        self
    }

    /// These limits, shared, as the state [`enforce`] takes.
    pub fn shared(self) -> Arc<RateLimits> {
        Arc::new(self)
    }

    /// Wraps `router` so these limits apply to its requests. Layers wrap only the
    /// routes registered before them, so call this where the session layer's
    /// `Cookie` is already visible and the routes it should cover exist.
    pub fn apply<S>(self, router: axum::Router<S>) -> axum::Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        router.layer(axum::middleware::from_fn_with_state(
            Arc::new(self),
            enforce,
        ))
    }

    fn key(&self, by: KeyBy, headers: &HeaderMap) -> String {
        match by {
            KeyBy::Session => format!("session:{}", session_key(headers)),
            KeyBy::ClientIp => self
                .client_ip_header
                .as_deref()
                .and_then(|name| headers.get(name))
                .and_then(|value| value.to_str().ok())
                .map(|ip| format!("ip:{}", ip.trim()))
                .unwrap_or_else(|| format!("session:{}", session_key(headers))),
        }
    }

    /// `None` when `path` may proceed, else how long until it may.
    fn check(&self, path: &str, headers: &HeaderMap) -> Option<u64> {
        let mut wait = None::<u64>;
        for limit in self
            .limits
            .iter()
            .filter(|limit| limit.paths.contains(&path))
        {
            let key = self.key(limit.key_by, headers);
            let verdict = limit.limiter.check_key(&key);
            if limit.limiter.len() > MAX_TRACKED_KEYS {
                limit.limiter.retain_recent();
            }
            if let Err(not_until) = verdict {
                let secs = not_until
                    .wait_time_from(limit.limiter.clock().now())
                    .as_secs()
                    .max(1);
                wait = Some(wait.map_or(secs, |current| current.max(secs)));
            }
        }
        wait
    }
}

/// A new visitor's very first request has no cookie yet; those share one bucket,
/// which only ever covers a single request per genuinely new visitor.
fn session_key(headers: &HeaderMap) -> String {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(';').find_map(|pair| {
                let (name, value) = pair.trim().split_once('=')?;
                (name == SESSION_COOKIE).then(|| value.to_string())
            })
        })
        .unwrap_or_else(|| "no-session".to_string())
}

/// The middleware behind [`RateLimits::apply`], for a router built as one
/// expression: `.layer(from_fn_with_state(limits.shared(), rate_limit::enforce))`.
pub async fn enforce(
    State(limits): State<Arc<RateLimits>>,
    request: Request,
    next: Next,
) -> Response {
    match limits.check(request.uri().path(), request.headers()) {
        None => next.run(request).await,
        Some(retry_after) => too_many_requests(retry_after),
    }
}

fn too_many_requests(retry_after_secs: u64) -> Response {
    let body = serde_json::json!({
        "message": "You're doing that too often. Please wait a moment and try again.",
        "code": 429,
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::RETRY_AFTER, retry_after_secs.to_string()),
        ],
        Body::from(body.to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{Router, http::HeaderValue, routing::post};
    use tower::ServiceExt;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    const SIGN_IN: &[&str] = &["/sign_in"];

    #[test]
    fn a_session_is_keyed_by_its_cookie_and_a_missing_one_shares_a_bucket() {
        let limits = RateLimits::new();
        assert_eq!(
            limits.key(KeyBy::Session, &headers(&[("cookie", "a=1; session=abc")])),
            "session:abc"
        );
        assert_eq!(
            limits.key(KeyBy::Session, &HeaderMap::new()),
            "session:no-session"
        );
    }

    #[test]
    fn the_address_is_used_only_when_a_header_is_named_and_present() {
        let named = RateLimits::new().client_ip_header("cf-connecting-ip");
        let both = headers(&[
            ("cf-connecting-ip", " 203.0.113.7 "),
            ("cookie", "session=abc"),
        ]);
        assert_eq!(named.key(KeyBy::ClientIp, &both), "ip:203.0.113.7");
        // No header on the request, or none configured: the session, never one shared bucket.
        assert_eq!(
            named.key(KeyBy::ClientIp, &headers(&[("cookie", "session=abc")])),
            "session:abc"
        );
        assert_eq!(RateLimits::new().key(KeyBy::ClientIp, &both), "session:abc");
    }

    #[test]
    fn a_limit_lets_a_burst_through_then_refuses_with_a_wait() {
        let limits = RateLimits::new().limit(Limit::per_hour(SIGN_IN, KeyBy::Session, 3));
        let visitor = headers(&[("cookie", "session=abc")]);
        for _ in 0..3 {
            assert_eq!(limits.check("/sign_in", &visitor), None);
        }
        let wait = limits
            .check("/sign_in", &visitor)
            .expect("the fourth is refused");
        assert!((1..=3600).contains(&wait), "{wait}");
        // Another visitor, and another path, are unaffected.
        assert_eq!(
            limits.check("/sign_in", &headers(&[("cookie", "session=other")])),
            None
        );
        assert_eq!(limits.check("/elsewhere", &visitor), None);
    }

    #[test]
    fn changing_session_does_not_reset_an_address_limit() {
        let limits = RateLimits::new()
            .client_ip_header("x-client-ip")
            .limit(Limit::per_hour(SIGN_IN, KeyBy::ClientIp, 2));
        let from = |session: &str| headers(&[("x-client-ip", "198.51.100.1"), ("cookie", session)]);
        assert_eq!(limits.check("/sign_in", &from("session=one")), None);
        assert_eq!(limits.check("/sign_in", &from("session=two")), None);
        assert!(limits.check("/sign_in", &from("session=three")).is_some());
    }

    #[tokio::test]
    async fn the_layer_answers_429_in_the_shape_the_client_reads() {
        let app = RateLimits::new()
            .limit(Limit::per_hour(SIGN_IN, KeyBy::Session, 1))
            .apply(Router::new().route("/sign_in", post(|| async { "ok" })));

        let call = || {
            Request::builder()
                .method("POST")
                .uri("/sign_in")
                .header("cookie", "session=abc")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(call()).await.unwrap().status(),
            StatusCode::OK
        );

        let refused = app.oneshot(call()).await.unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(refused.headers().contains_key(header::RETRY_AFTER));
        let bytes = axum::body::to_bytes(refused.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["code"], 429);
        assert!(payload["message"].as_str().unwrap().contains("too often"));
    }
}
