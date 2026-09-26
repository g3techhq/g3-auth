use proc_macro2::{TokenStream as TokenStream2, TokenTree};
use quote::quote;
use syn::{Attribute, Error, ItemFn, Lit, LitStr, Meta, spanned::Spanned};

const ROUTE_ATTRS: &[&str] = &["get", "post", "put", "patch", "delete", "server"];

fn route_name(attr: &Attribute) -> Option<String> {
    let name = attr.path().segments.last()?.ident.to_string();
    ROUTE_ATTRS.contains(&name.as_str()).then_some(name)
}

/// The route's path without its `?query` suffix: what a request's URI path
/// is compared against.
fn route_path(route: &Attribute) -> syn::Result<LitStr> {
    let Meta::List(list) = &route.meta else {
        return Err(Error::new(
            route.span(),
            "expected a path: `#[get(\"/api/...\")]`",
        ));
    };
    let first = list.tokens.clone().into_iter().next();
    let Some(TokenTree::Literal(literal)) = first else {
        return Err(Error::new(
            list.span(),
            "`#[public]` needs the route's path as its first argument: `#[get(\"/api/...\")]`",
        ));
    };
    let Lit::Str(text) = Lit::new(literal) else {
        return Err(Error::new(
            list.span(),
            "the route's path must be a string literal",
        ));
    };
    let value = text.value();
    let path = value.split('?').next().unwrap_or_default();
    if !path.starts_with('/') {
        return Err(Error::new(
            text.span(),
            "`#[public]` needs an absolute path starting with `/`",
        ));
    }
    Ok(LitStr::new(path, text.span()))
}

pub(crate) fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    if !attr.is_empty() {
        return Err(Error::new(attr.span(), "`#[public]` takes no arguments"));
    }
    let function: ItemFn = syn::parse2(item.clone())?;

    let Some((route, method)) = function
        .attrs
        .iter()
        .find_map(|attr| route_name(attr).map(|name| (attr, name)))
    else {
        return Err(Error::new(
            function.sig.ident.span(),
            "`#[public]` must be placed above the route attribute, e.g. `#[public]` then \
             `#[get(\"/api/...\")]`. Below it, the route attribute has already expanded and \
             its path can no longer be read.",
        ));
    };
    if method == "server" {
        return Err(Error::new(
            route.span(),
            "`#[public]` needs an explicit path, and `#[server]` derives its own. Use \
             `#[post(\"/api/...\")]` instead.",
        ));
    }
    let path = route_path(route)?;

    Ok(quote! {
        #item
        ::g3_auth::__private::public_endpoint!(#path);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(attr: TokenStream2, item: TokenStream2) -> String {
        expand(attr, item).unwrap_err().to_string()
    }

    #[test]
    fn registers_the_path_without_its_query() {
        let out = expand(
            quote!(),
            quote! {
                #[get("/api/v1/trending?media_type", db: Db)]
                pub async fn trending(media_type: Option<MediaType>) -> Result<Vec<Media>> { .. }
            },
        )
        .unwrap()
        .to_string();
        assert!(out.contains("public_endpoint ! (\"/api/v1/trending\")"));
        // The function itself is left for the route attribute to expand.
        assert!(out.contains("# [get (\"/api/v1/trending?media_type\" , db : Db)]"));
    }

    #[test]
    fn keeps_path_parameters() {
        let out = expand(
            quote!(),
            quote! {
                #[post("/api/v1/games/{game_id}/join", ctx: SessionContext)]
                pub async fn join(game_id: String) -> Result<()> { Ok(()) }
            },
        )
        .unwrap()
        .to_string();
        assert!(out.contains("public_endpoint ! (\"/api/v1/games/{game_id}/join\")"));
    }

    #[test]
    fn sits_above_other_attributes_too() {
        let out = expand(
            quote!(),
            quote! {
                #[cache_shared(cdn = 300)]
                #[get("/api/v1/trending")]
                pub async fn trending() -> Result<Vec<Media>> { Ok(vec![]) }
            },
        );
        assert!(out.is_ok());
    }

    #[test]
    fn refuses_being_placed_below_the_route() {
        let bare = quote! {
            pub async fn is_signed_in() -> Result<bool> { Ok(true) }
        };
        assert!(error(quote!(), bare).contains("must be placed above"));
    }

    #[test]
    fn refuses_server_functions_and_bad_paths() {
        let server = quote! {
            #[server]
            pub async fn rate() -> Result<()> { Ok(()) }
        };
        assert!(error(quote!(), server).contains("explicit path"));

        let relative = quote! {
            #[get("api/v1/user")]
            pub async fn user() -> Result<()> { Ok(()) }
        };
        assert!(error(quote!(), relative).contains("starting with `/`"));
    }

    #[test]
    fn refuses_arguments() {
        let item = quote! {
            #[get("/api/v1/user")]
            pub async fn user() -> Result<()> { Ok(()) }
        };
        assert!(error(quote!(always), item).contains("takes no arguments"));
    }
}
