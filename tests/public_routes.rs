//! `#[derive(PublicRoutes)]` on a real `Routable` enum shaped like
//! greenside's: a catch-all redirect, layouts, nested dynamic segments and
//! query-only routes. The derive has to agree with the paths `Routable`
//! renders, and must never let the redirect make a path public.
#![cfg(feature = "auth")]
#![allow(non_snake_case)]

use dioxus::prelude::*;
// Imported beside the derive's `#[public]` helper on purpose: the two must
// not clash when a module uses both.
use g3_core::auth::PublicRoutes;
#[allow(unused_imports)]
use g3_core::public;

#[derive(Clone, Debug, PartialEq, Routable, PublicRoutes)]
#[rustfmt::skip]
enum Route {
    #[layout(Shell)]
        #[redirect("/:..segments", |segments: Vec<String>| { drop(segments); Route::LoadingScreen {} })]
        #[public]
        #[route("/")]
        LoadingScreen {},
    #[nest("/signin")]
        #[public]
        #[route("/options?:redirect")]
        SigninOptions { redirect: String },
        #[route("/settings?:redirect")]
        SigninSettings { redirect: String },
    #[end_nest]
    #[route("/games?:tab")]
    Games { tab: String },
    #[nest("/games")]
        #[nest("/:game_id")]
            #[public]
            #[route("/join")]
            JoinGame { game_id: String },
            #[route("?:tab")]
            PendingGame { game_id: String, tab: String },
        #[end_nest]
    #[end_nest]
    #[nest("/tourneys/:tourney_id/games/:game_id")]
        #[public]
        #[route("/join?:owner_code")]
        JoinTourneyGame { tourney_id: String, game_id: String, owner_code: String },
    #[end_nest]
    #[nest("/account")]
        #[public]
        #[route("/privacy_policy")]
        PrivacyPolicy {},
        #[route("/delete")]
        DeleteAccount {},
}

#[component]
fn Shell() -> Element {
    rsx! { Outlet::<Route> {} }
}
#[component]
fn LoadingScreen() -> Element {
    rsx! {}
}
#[component]
fn SigninOptions(redirect: String) -> Element {
    rsx! {}
}
#[component]
fn SigninSettings(redirect: String) -> Element {
    rsx! {}
}
#[component]
fn Games(tab: String) -> Element {
    rsx! {}
}
#[component]
fn JoinGame(game_id: String) -> Element {
    rsx! {}
}
#[component]
fn PendingGame(game_id: String, tab: String) -> Element {
    rsx! {}
}
#[component]
fn JoinTourneyGame(tourney_id: String, game_id: String, owner_code: String) -> Element {
    rsx! {}
}
#[component]
fn PrivacyPolicy() -> Element {
    rsx! {}
}
#[component]
fn DeleteAccount() -> Element {
    rsx! {}
}

#[test]
fn the_patterns_are_the_marked_pages() {
    assert_eq!(
        Route::PUBLIC_PATTERNS,
        [
            "/",
            "/signin/options",
            "/games/:game_id/join",
            "/tourneys/:tourney_id/games/:game_id/join",
            "/account/privacy_policy",
        ]
    );
}

#[test]
fn every_marked_page_renders_to_a_public_path() {
    // What `Routable` itself renders for each page must pass the check,
    // or a link the app generates would be redirected.
    let public = [
        Route::LoadingScreen {},
        Route::SigninOptions {
            redirect: "/games".into(),
        },
        Route::JoinGame {
            game_id: "game:k3j2h1".into(),
        },
        Route::JoinTourneyGame {
            tourney_id: "tourney:t1".into(),
            game_id: "game:g1".into(),
            owner_code: "abc".into(),
        },
        Route::PrivacyPolicy {},
    ];
    for route in public {
        assert!(route.is_public(), "{route:?}");
        let path = route.to_string();
        assert!(Route::is_public_path(&path), "{path}");
        // And back again: the path really is that page.
        assert_eq!(path.parse::<Route>().unwrap(), route);
    }
}

#[test]
fn other_pages_stay_guarded() {
    let guarded = [
        Route::SigninSettings {
            redirect: String::new(),
        },
        Route::Games {
            tab: "Pending".into(),
        },
        Route::PendingGame {
            game_id: "game:g1".into(),
            tab: "Players".into(),
        },
        Route::DeleteAccount {},
    ];
    for route in guarded {
        assert!(!route.is_public(), "{route:?}");
        assert!(!Route::is_public_path(&route.to_string()), "{route}");
    }
}

#[test]
fn the_catch_all_redirect_opens_nothing() {
    // Each of these parses as `LoadingScreen` through the redirect, which
    // is public. Matching on the parsed value would let them all through.
    for path in [
        "/api/v1/games",
        "/api/v1/delete_account",
        "/no/such/page",
        "/games/g1/leave",
    ] {
        assert_eq!(path.parse::<Route>().unwrap(), Route::LoadingScreen {});
        assert!(!Route::is_public_path(path), "{path}");
    }
}

#[test]
fn share_links_match_in_either_encoding() {
    assert!(Route::is_public_path("/games/game:k3j2h1/join"));
    assert!(Route::is_public_path("/games/game%3Ak3j2h1/join"));
    assert!(Route::is_public_path("/signin/options?redirect=%2Fgames"));
}

#[cfg(feature = "server")]
mod guard {
    use super::Route;
    use g3_core::auth::AuthGuard;

    #[test]
    fn the_guard_uses_the_marked_pages() {
        let guard = AuthGuard::for_routes(Route::LoadingScreen {});
        assert_eq!(guard.splash(), "/");
        assert!(guard.allows_signed_out("/signin/options"));
        assert!(guard.allows_signed_out("/games/game:g1/join"));
        assert!(!guard.allows_signed_out("/games"));
        assert!(!guard.allows_signed_out("/api/v1/games"));
    }

    #[test]
    #[should_panic(expected = "must be a public page")]
    fn a_guarded_splash_is_refused() {
        AuthGuard::for_routes(Route::DeleteAccount {});
    }
}
