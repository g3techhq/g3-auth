use std::{collections::HashSet, sync::LazyLock};

/// A server function reachable without a session, registered by
/// [`public`](crate::public). Collected at startup; see
/// [`public_endpoints`].
#[derive(Debug)]
pub struct PublicEndpoint {
    path: &'static str,
}

impl PublicEndpoint {
    #[doc(hidden)]
    pub const fn new(path: &'static str) -> Self {
        Self { path }
    }

    /// The route's path, without any `?query` suffix. `{param}` segments
    /// match any one segment.
    pub const fn path(&self) -> &'static str {
        self.path
    }
}

inventory::collect!(PublicEndpoint);

struct Registry {
    exact: HashSet<&'static str>,
    /// Paths with `{param}` segments, split into segments.
    patterns: Vec<Vec<&'static str>>,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let mut registry = Registry {
        exact: HashSet::new(),
        patterns: Vec::new(),
    };
    for endpoint in inventory::iter::<PublicEndpoint> {
        if endpoint.path.contains('{') {
            registry.patterns.push(endpoint.path.split('/').collect());
        } else {
            registry.exact.insert(endpoint.path);
        }
    }
    registry
});

fn matches_pattern(pattern: &[&str], path: &str) -> bool {
    let mut segments = path.split('/');
    for expected in pattern {
        let Some(segment) = segments.next() else {
            return false;
        };
        // `{*rest}` takes the rest of the path, however long.
        if expected.starts_with("{*") {
            return true;
        }
        let is_param = expected.starts_with('{') && expected.ends_with('}');
        if is_param {
            if segment.is_empty() {
                return false;
            }
        } else if segment != *expected {
            return false;
        }
    }
    segments.next().is_none()
}

/// Whether `path` (a request's URI path, no query) belongs to a server
/// function marked [`public`](crate::public).
pub fn is_public_endpoint(path: &str) -> bool {
    REGISTRY.exact.contains(path)
        || REGISTRY
            .patterns
            .iter()
            .any(|pattern| matches_pattern(pattern, path))
}

/// Every registered public path, sorted. Worth pinning in a test, so that
/// opening an endpoint up always shows as a reviewed change:
///
/// ```ignore
/// assert_eq!(g3_auth::public_endpoints(), ["/api/v1/is_signed_in", "/api/v1/user"]);
/// ```
pub fn public_endpoints() -> Vec<&'static str> {
    let mut paths: Vec<_> = inventory::iter::<PublicEndpoint>
        .into_iter()
        .map(PublicEndpoint::path)
        .collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    inventory::submit!(PublicEndpoint::new("/api/test/exact"));
    inventory::submit!(PublicEndpoint::new("/api/test/games/{game_id}/join"));
    inventory::submit!(PublicEndpoint::new("/api/test/files/{*rest}"));

    #[test]
    fn exact_paths() {
        assert!(is_public_endpoint("/api/test/exact"));
        assert!(!is_public_endpoint("/api/test/exact/more"));
        assert!(!is_public_endpoint("/api/test/exac"));
        assert!(!is_public_endpoint("/api/test/exact/"));
    }

    #[test]
    fn parameters_match_one_segment() {
        assert!(is_public_endpoint("/api/test/games/game:abc/join"));
        assert!(!is_public_endpoint("/api/test/games//join"));
        assert!(!is_public_endpoint("/api/test/games/a/b/join"));
        assert!(!is_public_endpoint("/api/test/games/abc/leave"));
        assert!(!is_public_endpoint("/api/test/games/abc/join/extra"));
    }

    #[test]
    fn wildcards_take_the_rest() {
        assert!(is_public_endpoint("/api/test/files/a/b/c"));
        assert!(!is_public_endpoint("/api/test/other/a"));
    }

    #[test]
    fn lists_every_path_sorted() {
        let paths = public_endpoints();
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(paths.contains(&"/api/test/exact"));
    }
}
