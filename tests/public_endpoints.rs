//! `#[public]` on real Dioxus server functions: it has to expand before the
//! route attribute, and the path it registers has to be the one the guard
//! sees.
#![cfg(all(feature = "auth", feature = "server", feature = "cache"))]

use dioxus::prelude::*;
use g3_kit::{auth, cache_shared, public};

#[public]
#[get("/api/it/is_signed_in")]
async fn is_signed_in() -> Result<bool> {
    Ok(false)
}

#[public]
#[post("/api/it/games/{game_id}/join")]
async fn join(game_id: String) -> Result<String> {
    Ok(game_id)
}

// Both attributes read the same route attribute, in either order.
#[public]
#[cache_shared(cdn = 60)]
#[get("/api/it/trending?page")]
async fn trending(page: Option<u32>) -> Result<Vec<u32>> {
    Ok(vec![page.unwrap_or_default()])
}

#[get("/api/it/private")]
async fn private() -> Result<u8> {
    Ok(1)
}

#[test]
fn marked_functions_are_public_and_nothing_else_is() {
    assert!(auth::is_public_endpoint("/api/it/is_signed_in"));
    assert!(auth::is_public_endpoint("/api/it/games/game:abc/join"));
    assert!(auth::is_public_endpoint("/api/it/trending"));
    assert!(!auth::is_public_endpoint("/api/it/private"));
    assert!(!auth::is_public_endpoint("/api/it/games/game:abc/leave"));

    assert_eq!(
        auth::public_endpoints(),
        [
            "/api/it/games/{game_id}/join",
            "/api/it/is_signed_in",
            "/api/it/trending",
        ]
    );
}

#[tokio::test]
async fn the_functions_still_run() {
    assert!(!is_signed_in().await.unwrap());
    assert_eq!(join("g1".into()).await.unwrap(), "g1");
    assert_eq!(private().await.unwrap(), 1);
    assert_eq!(trending(Some(2)).await.unwrap(), vec![2]);
}
