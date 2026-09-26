use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Attribute, Error, Fields, ItemEnum, LitStr, Meta, spanned::Spanned};

/// The route pattern without its `?query` or `#hash` part: what a request's
/// URI path is compared against.
fn path_part(pattern: &str) -> &str {
    pattern.split(['?', '#']).next().unwrap_or_default()
}

fn literal_arg(attr: &Attribute, what: &str) -> syn::Result<LitStr> {
    match &attr.meta {
        Meta::List(list) => {
            // `#[redirect("/..", closure)]` and friends: the path comes first.
            let first = list.tokens.clone().into_iter().next();
            let tokens: TokenStream2 = first.into_iter().collect();
            syn::parse2::<LitStr>(tokens)
                .map_err(|_| Error::new(list.span(), format!("expected `#[{what}(\"/path\")]`")))
        }
        _ => Err(Error::new(
            attr.span(),
            format!("expected `#[{what}(\"/path\")]`"),
        )),
    }
}

/// The full path of every variant marked `#[public]`, and the variants
/// themselves, read in declaration order the way `Routable` reads them:
/// `#[nest]` opens a prefix, `#[end_nest]` closes it, layouts don't touch
/// the path, and redirects are never pages.
pub(crate) fn public_routes(item: &ItemEnum) -> syn::Result<Vec<(syn::Variant, String)>> {
    let mut nests: Vec<String> = Vec::new();
    let mut public = Vec::new();

    for variant in &item.variants {
        let mut route = None;
        let mut marked = None;
        let mut child = None;
        for attr in &variant.attrs {
            let Some(name) = attr.path().get_ident().map(ToString::to_string) else {
                continue;
            };
            match name.as_str() {
                "nest" => nests.push(path_part(&literal_arg(attr, "nest")?.value()).to_string()),
                // The guard does the pop; a successful one falls through to `_`.
                "end_nest" if nests.pop().is_none() => {
                    return Err(Error::new(attr.span(), "`#[end_nest]` without a `#[nest]`"));
                }
                "route" => route = Some(literal_arg(attr, "route")?),
                "child" => child = Some(attr),
                "public" => {
                    if !matches!(attr.meta, Meta::Path(_)) {
                        return Err(Error::new(attr.span(), "`#[public]` takes no arguments"));
                    }
                    if marked.is_some() {
                        return Err(Error::new(attr.span(), "duplicate `#[public]`"));
                    }
                    marked = Some(attr);
                }
                _ => {}
            }
        }

        let Some(marked) = marked else { continue };
        if let Some(child) = child {
            return Err(Error::new(
                child.span(),
                "`#[public]` can't see into a `#[child]` router. Mark the child's own \
                 routes with `#[derive(PublicRoutes)]` and check them in `public_page`.",
            ));
        }
        let Some(route) = route else {
            return Err(Error::new(
                marked.span(),
                "`#[public]` needs a `#[route(\"/path\")]` on the same variant",
            ));
        };
        let full = format!("{}{}", nests.concat(), path_part(&route.value()));
        if !full.starts_with('/') {
            return Err(Error::new(route.span(), "a route path must start with `/`"));
        }
        let first = full.split('/').find(|segment| !segment.is_empty());
        if first.is_some_and(|segment| segment.starts_with(":..")) {
            return Err(Error::new(
                marked.span(),
                format!(
                    "`{full}` matches every path, including every server function, so marking \
                     it `#[public]` would switch the guard off. A not-found page doesn't need \
                     it: a signed-out visitor is sent to the splash instead."
                ),
            ));
        }
        public.push((variant.clone(), full));
    }
    Ok(public)
}

pub(crate) fn expand(item: TokenStream2) -> syn::Result<TokenStream2> {
    let item: ItemEnum = syn::parse2(item)?;
    let public = public_routes(&item)?;
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    let patterns = public.iter().map(|(_, path)| path);
    let arms = public.iter().map(|(variant, _)| {
        let ident = &variant.ident;
        match variant.fields {
            Fields::Named(_) => quote!(#name::#ident { .. }),
            Fields::Unnamed(_) => quote!(#name::#ident(..)),
            Fields::Unit => quote!(#name::#ident),
        }
    });
    let is_public = if public.is_empty() {
        quote!(false)
    } else {
        quote!(matches!(self, #(#arms)|*))
    };

    Ok(quote! {
        impl #impl_generics ::g3_auth::PublicRoutes for #name #ty_generics #where_clause {
            const PUBLIC_PATTERNS: &'static [&'static str] = &[#(#patterns),*];

            fn is_public(&self) -> bool {
                #is_public
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(item: TokenStream2) -> Vec<String> {
        public_routes(&syn::parse2(item).unwrap())
            .unwrap()
            .into_iter()
            .map(|(_, path)| path)
            .collect()
    }

    fn error(item: TokenStream2) -> String {
        match public_routes(&syn::parse2(item).unwrap()) {
            Ok(_) => panic!("expected an error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn follows_nests_like_routable() {
        // greenside's shape: a catch-all redirect, nested dynamic segments,
        // layouts, and query-only routes.
        let found = patterns(quote! {
            enum Route {
                #[layout(NativeBackLayout)]
                    #[redirect("/:..segments", |segments: Vec<String>| Route::LoadingScreen {})]
                    #[public]
                    #[route("/")]
                    LoadingScreen {},
                #[nest("/signin")]
                    #[layout(Signin)]
                        #[public]
                        #[route("/options?:redirect")]
                        SigninOptions { redirect: Option<String> },
                        #[route("/settings?:redirect")]
                        SigninSettings { redirect: Option<String> },
                    #[end_layout]
                #[end_nest]
                #[nest("/games")]
                    #[nest("/:game_id")]
                        #[public]
                        #[route("/join")]
                        JoinGame { game_id: String },
                        #[route("?:tab")]
                        PendingGame { game_id: String, tab: PendingGameTab },
                    #[end_nest]
                #[end_nest]
                #[nest("/account")]
                    #[public]
                    #[transition(layer = sheet)]
                    #[route("/privacy_policy")]
                    PrivacyPolicy {},
            }
        });
        assert_eq!(
            found,
            [
                "/",
                "/signin/options",
                "/games/:game_id/join",
                "/account/privacy_policy"
            ]
        );
    }

    #[test]
    fn generates_the_impl() {
        let out = expand(quote! {
            enum Route {
                #[public]
                #[route("/")]
                Splash {},
                #[route("/home")]
                Home {},
            }
        })
        .unwrap()
        .to_string();
        assert!(out.contains("PUBLIC_PATTERNS"));
        assert!(out.contains("& [\"/\"]"));
        assert!(out.contains("matches ! (self , Route :: Splash { .. })"));
    }

    #[test]
    fn no_public_routes_is_allowed() {
        let out = expand(quote! {
            enum Route {
                #[route("/")]
                Home {},
            }
        })
        .unwrap()
        .to_string();
        assert!(out.contains("fn is_public (& self) -> bool { false }"));
    }

    #[test]
    fn refuses_a_public_catch_all() {
        assert!(
            error(quote! {
                enum Route {
                    #[public]
                    #[route("/:..route")]
                    NotFound { route: Vec<String> },
                }
            })
            .contains("matches every path")
        );
        // Inside a nest, it only covers that nest.
        let found = patterns(quote! {
            enum Route {
                #[nest("/docs")]
                    #[public]
                    #[route("/:..page")]
                    Docs { page: Vec<String> },
            }
        });
        assert_eq!(found, ["/docs/:..page"]);
    }

    #[test]
    fn refuses_mistakes() {
        assert!(
            error(quote! {
                enum Route {
                    #[public]
                    #[child("/nested")]
                    Nested { child: Child },
                }
            })
            .contains("`#[child]`")
        );
        assert!(
            error(quote! {
                enum Route {
                    #[public(always)]
                    #[route("/")]
                    Home {},
                }
            })
            .contains("no arguments")
        );
        assert!(
            error(quote! {
                enum Route {
                    #[end_nest]
                    #[route("/")]
                    Home {},
                }
            })
            .contains("without a `#[nest]`")
        );
    }
}
