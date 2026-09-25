//! Proc macros for [g3-core](https://docs.rs/g3-core). Use them through
//! `g3_core::cache_shared` and `g3_core::public`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;

mod cache;
mod public;

/// Caches a server function whose answer is the same for every visitor: at
/// the CDN, on the server, or both.
///
/// Place it **above** the route attribute:
///
/// ```ignore
/// #[g3_core::cache_shared(cdn = 300, server = "5m")]
/// #[get("/api/trending?media_type", db: Db)]
/// pub async fn get_trending(media_type: Option<MediaType>) -> Result<Vec<Media>> { .. }
/// ```
///
/// # Arguments
///
/// - `cdn = <seconds>`: CDN caching. Successful responses are marked
///   `public, max-age=60, s-maxage=<seconds>` (see `g3_core::cache::cdn`).
/// - `server = "<duration>"`: server caching, e.g. `"30s"`, `"5m"`, `"1h"`,
///   `"1d"`. The whole function's `Ok` answer is kept per set of arguments;
///   concurrent misses share one call and errors are not kept.
/// - `capacity = <entries>`: the most answers the server cache keeps.
///   Default 10 000.
/// - `trust_extractors`: skips the extractor check below, for an extractor
///   whose name looks per-visitor but isn't.
///
/// At least one of `cdn` and `server` is required.
///
/// # Checked at compile time
///
/// - The function uses `#[get]`: a CDN never caches other methods, and
///   shared data is read, not written.
/// - No extractor in the route attribute is named like per-visitor state
///   (`session`, `auth`, `user`, `cookie`, `token`, `claims`, `header`...),
///   and the body doesn't call `FullstackContext`. Either would make the
///   answer depend on who asks, and sharing it would show one visitor's
///   data to everyone.
/// - The function is `async` and returns a `Result`.
///
/// # Not checked
///
/// A function can depend on the visitor in ways no macro can see: a query
/// that uses the database session's user, a global, a value from an
/// extractor with a neutral name. Only share functions whose answer comes
/// entirely from their arguments and public data.
#[proc_macro_attribute]
pub fn cache_shared(attr: TokenStream, item: TokenStream) -> TokenStream {
    report(cache::expand(attr.into(), item.clone().into()), item)
}

/// Marks a server function as reachable without a session.
///
/// g3-core's auth guard denies every request that has no signed-in user,
/// unless its path is a static asset, a public page the app names, or a
/// server function marked with this attribute. Place it **above** the route
/// attribute:
///
/// ```ignore
/// #[g3_core::public]
/// #[get("/api/v1/is_signed_in", ctx: SessionContext)]
/// pub async fn is_signed_in() -> Result<bool> { .. }
/// ```
///
/// Forgetting it is the safe mistake: the endpoint answers a signed-out
/// caller with `401`. Adding it is a deliberate, reviewable line next to the
/// function it opens up, so say why in a comment.
///
/// # Checked at compile time
///
/// - It sits above a `#[get]`, `#[post]`, `#[put]`, `#[patch]` or `#[delete]`
///   with an explicit path. Below it, the route attribute has already
///   expanded; `#[server]` derives its path at build time.
/// - The path starts with `/`. A `?query` suffix is ignored, and `{param}`
///   segments match any one segment.
///
/// In a build without `g3-core/server` it registers nothing, so client
/// builds compile the same code.
#[proc_macro_attribute]
pub fn public(attr: TokenStream, item: TokenStream) -> TokenStream {
    report(public::expand(attr.into(), item.clone().into()), item)
}

/// The expansion, or the item unchanged plus the error, so one mistake
/// doesn't also bury the function under "cannot find" errors.
fn report(result: syn::Result<TokenStream2>, item: TokenStream) -> TokenStream {
    match result {
        Ok(tokens) => tokens.into(),
        Err(err) => {
            let mut item: TokenStream2 = item.into();
            item.extend(err.to_compile_error());
            item.into()
        }
    }
}
