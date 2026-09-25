/// The pages of a `Routable` enum a signed-out visitor may load. Derive it
/// with [`PublicRoutes`](derive@PublicRoutes) and mark those pages
/// `#[public]`.
///
/// On the server, [`AuthGuard::for_routes`](super::AuthGuard::for_routes)
/// uses [`is_public_path`](Self::is_public_path) to let their page loads
/// through.
pub trait PublicRoutes {
    /// Each public page's full path pattern, as Dioxus writes it: `:param`
    /// is one segment, `:..rest` is the rest of the path.
    const PUBLIC_PATTERNS: &'static [&'static str];

    /// Whether this page is marked `#[public]`.
    fn is_public(&self) -> bool;

    /// Whether a request for `path` loads a public page.
    ///
    /// Matched against [`PUBLIC_PATTERNS`](Self::PUBLIC_PATTERNS), never by
    /// parsing `path` into the enum: a catch-all `#[redirect]` would turn
    /// every unknown path into its target.
    fn is_public_path(path: &str) -> bool {
        let path = path.split(['?', '#']).next().unwrap_or_default();
        Self::PUBLIC_PATTERNS
            .iter()
            .any(|pattern| route_pattern_matches(pattern, path))
    }
}

pub use g3_kit_macros::PublicRoutes;

/// Whether `path` matches a Dioxus route pattern. Empty segments are
/// ignored on both sides, so `/games` and `/games/` are the same page.
fn route_pattern_matches(pattern: &str, path: &str) -> bool {
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    for expected in pattern.split('/').filter(|segment| !segment.is_empty()) {
        if expected.starts_with(":..") {
            return true;
        }
        let Some(segment) = segments.next() else {
            return false;
        };
        if !expected.starts_with(':') && segment != expected {
            return false;
        }
    }
    segments.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::route_pattern_matches as matches;

    #[test]
    fn static_paths() {
        assert!(matches("/", "/"));
        assert!(!matches("/", "/games"));
        assert!(matches("/signin/options", "/signin/options"));
        assert!(matches("/signin/options", "/signin/options/"));
        assert!(!matches("/signin/options", "/signin"));
        assert!(!matches("/signin/options", "/signin/options/extra"));
    }

    #[test]
    fn parameters_match_one_segment() {
        assert!(matches("/games/:game_id/join", "/games/game:k3j2h1/join"));
        assert!(matches("/games/:game_id/join", "/games/game%3Ak3j2h1/join"));
        assert!(!matches("/games/:game_id/join", "/games/join"));
        assert!(!matches("/games/:game_id/join", "/games/a/b/join"));
        assert!(!matches("/games/:game_id/join", "/games/a/leave"));
    }

    #[test]
    fn a_catch_all_takes_the_rest() {
        assert!(matches("/docs/:..rest", "/docs"));
        assert!(matches("/docs/:..rest", "/docs/a/b"));
        assert!(!matches("/docs/:..rest", "/other"));
    }
}
