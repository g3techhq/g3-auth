use dioxus::prelude::*;
use g3_ui::{Button, ButtonExpand, ButtonFill, Color, Text, TextVariant};

use super::GoogleSignedIn;

/// Google's own sign-in button, drawn by Google's script into this element.
const CONTAINER_ID: &str = "g3-google-signin";

/// Renders Google's button into the container, loading the script once. In
/// redirect mode Google posts the signed token straight to the callback and
/// the browser follows the server's redirect, so nothing here sees the
/// result. Not `ux_mode: "popup"` and not `prompt()` (One Tap): those need a
/// handler in the page, and the redirect is what the server router expects.
const RENDER_SCRIPT: &str = r#"
(() => {
    const container = document.getElementById("g3-google-signin");
    if (!container || container.dataset.rendered === "true") return;

    const renderButton = () => {
        if (!window.google?.accounts?.id) {
            console.error("[g3-auth] Google Identity Services did not initialize");
            return;
        }
        const clientId = container.dataset.clientId;
        if (!clientId) {
            console.error("[g3-auth] Google OAuth client ID is not configured");
            return;
        }
        google.accounts.id.initialize({
            client_id: clientId,
            ux_mode: "redirect",
            login_uri: new URL("/api/v1/google_signin_callback", window.location.origin).href,
        });
        google.accounts.id.renderButton(container, {
            type: "standard",
            theme: "outline",
            size: "large",
            text: "signin_with",
            shape: "rectangular",
            logo_alignment: "left",
            width: Math.floor(container.getBoundingClientRect().width),
        });
        container.dataset.rendered = "true";
    };

    if (window.google?.accounts?.id) {
        renderButton();
        return;
    }
    let script = document.getElementById("google-identity-services");
    if (!script) {
        script = document.createElement("script");
        script.id = "google-identity-services";
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.defer = true;
        document.head.appendChild(script);
    }
    script.addEventListener("load", renderButton, { once: true });
    script.addEventListener(
        "error",
        () => console.error("[g3-auth] Failed to load Google Identity Services"),
        { once: true },
    );
})();
"#;

/// Android signs in through the system's Credential Manager. Google's web
/// button needs a page origin Google has registered, and the WebView's is
/// `https://dioxus.index.html`, which it refuses as a redirect URI. Android
/// never hydrates server HTML, so it may render a different tree.
const NATIVE: bool = cfg!(target_os = "android");

/// Google's "G" in its own colors, which its branding requires on a sign-in
/// button. The web button draws its own; the native and unconfigured buttons
/// are ours.
fn google_logo() -> Element {
    rsx! {
        svg {
            xmlns: "http://www.w3.org/2000/svg",
            view_box: "0 0 48 48",
            width: "18",
            height: "18",
            "aria-hidden": "true",
            path { fill: "#EA4335", d: "M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" }
            path { fill: "#4285F4", d: "M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" }
            path { fill: "#FBBC05", d: "M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" }
            path { fill: "#34A853", d: "M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" }
        }
    }
}

/// Asks the system for a Google ID token and waits for the answer, the same
/// start-and-poll the native plugin documents.
#[cfg(target_os = "android")]
async fn native_credential(
    plugins: &mut g3_native_plugins::NativePlugins,
    client_id: &str,
) -> Result<String, String> {
    plugins.auth.write().start_google_auth(client_id)?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(120);
    loop {
        if start.elapsed() >= timeout {
            return Err("Google sign-in timed out.".to_string());
        }
        if !plugins.auth.write().is_auth_awaiting() {
            // No token when the user backs out, or when the web client id is
            // not registered with an Android client for this package and
            // signing key; the plugin cannot tell them apart.
            return plugins.auth.write().poll_auth_result()?.ok_or_else(|| {
                "Google sign-in was cancelled, or this app is not registered with Google."
                    .to_string()
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Posts the token to the callback the web button uses, which checks it and
/// starts the session. Asking for JSON gets the destination back instead of a
/// redirect to a whole page.
#[cfg(target_os = "android")]
async fn post_credential(credential: String) -> Result<GoogleSignedIn, String> {
    let client = dioxus::fullstack::GLOBAL_REQUEST_CLIENT
        .get()
        .ok_or_else(|| "The Google sign-in client is unavailable.".to_string())?;
    let response = client
        .post(format!(
            "{}{}",
            dioxus::fullstack::get_server_url(),
            super::GOOGLE_CALLBACK_PATH
        ))
        .header("accept", "application/json")
        .form(&super::GoogleCallback { credential })
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err("Google sign-in could not be completed.".to_string());
    }
    let body = response.text().await.map_err(|error| error.to_string())?;
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

/// "Sign in with Google", on every platform. Put it where the button goes.
///
/// - **Web:** Google's own button; the browser is redirected by the server
///   once the token is checked, so there is nothing to handle.
/// - **Android:** a button that opens the system account picker, then signs
///   in and calls `on_signed_in` with where the server would have sent the
///   browser.
/// - **No client id configured**, or a platform with no flow: a disabled
///   button, so the screen keeps its shape.
///
/// The server half is [`google_router`](super::google_router).
#[component]
pub fn GoogleSignIn(
    /// The web OAuth client id. Defaults to `GOOGLE_OAUTH_CLIENT_ID` as it was
    /// at build time ([`client_id`](super::client_id)).
    client_id: Option<String>,
    /// Called after a native sign-in with the path to show next. Defaults to
    /// navigating there. Never called on the web, where the browser follows
    /// the server's redirect instead.
    on_signed_in: Option<EventHandler<GoogleSignedIn>>,
    /// Button text. Defaults to "Sign in with Google".
    label: Option<String>,
    /// Disable the button, for another sign-in in progress.
    disabled: Option<bool>,
) -> Element {
    let client_id = client_id.or_else(|| super::client_id().map(str::to_owned));
    let label = label.unwrap_or_else(|| "Sign in with Google".to_string());
    let disabled = disabled.unwrap_or(false);

    let mut error = use_signal(|| None::<String>);
    let mut pending = use_signal(|| false);
    #[cfg(target_os = "android")]
    let plugins = use_context::<g3_native_plugins::NativePlugins>();

    // Runs after render, on the client only, so the server and the first
    // client render agree on the markup.
    use_effect(move || {
        if !NATIVE {
            let _ = document::eval(RENDER_SCRIPT);
        }
    });

    let configured = client_id.is_some();
    let native_client_id = client_id.clone();
    let on_click = move |_| {
        #[cfg(target_os = "android")]
        {
            let Some(client_id) = native_client_id.clone() else {
                return;
            };
            pending.set(true);
            error.set(None);
            let mut plugins = plugins;
            spawn(async move {
                let result = async {
                    let credential = native_credential(&mut plugins, &client_id).await?;
                    post_credential(credential).await
                }
                .await;
                match result {
                    Ok(signed_in) => match on_signed_in {
                        Some(handler) => handler.call(signed_in),
                        None => {
                            navigator().push(signed_in.destination);
                        }
                    },
                    Err(message) => error.set(Some(message)),
                }
                pending.set(false);
            });
        }
        #[cfg(not(target_os = "android"))]
        let _ = (&native_client_id, &on_signed_in, &mut error, &mut pending);
    };

    rsx! {
        if !NATIVE && let Some(client_id) = client_id.as_deref() {
            div { class: "w-full",
                div {
                    id: CONTAINER_ID,
                    class: "w-full min-h-10",
                    "data-client-id": client_id,
                }
            }
        } else {
            Button {
                fill: ButtonFill::Outline,
                color: Color::Neutral,
                expand: ButtonExpand::Block,
                disabled: !NATIVE || !configured || disabled || pending(),
                start: google_logo(),
                onclick: on_click,
                "{label}"
            }
        }
        if let Some(message) = error() {
            Text { variant: TextVariant::Caption, color: Color::Danger, "{message}" }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn google_sign_in_uses_the_supported_rendered_button_flow() {
        let source = include_str!("component.rs");
        let implementation = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module must follow the implementation");

        assert!(implementation.contains("google.accounts.id.renderButton(container"));
        assert!(implementation.contains("ux_mode: \"redirect\""));
        assert!(implementation.contains("window.location.origin"));
        assert!(!implementation.contains("google.accounts.id.prompt()"));
        assert!(!implementation.contains("g_id_onload"));
        assert!(!implementation.contains("g_id_signin"));
    }

    #[test]
    fn android_signs_in_with_google_through_the_native_plugin() {
        let source = include_str!("component.rs");
        // The web button's origin on Android is `https://dioxus.index.html`,
        // which Google rejects; the system credential flow has no origin.
        assert!(source.contains("const NATIVE: bool = cfg!(target_os = \"android\")"));
        assert!(source.contains("start_google_auth(client_id)"));
        assert!(source.contains("super::GOOGLE_CALLBACK_PATH"));
        assert!(
            source.contains("if !NATIVE {\n            let _ = document::eval(RENDER_SCRIPT);")
        );
    }
}
