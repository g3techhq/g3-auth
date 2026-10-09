use dioxus::prelude::*;
use g3_ui::{Button, ButtonExpand, ButtonFill, Color, Text, TextVariant};

use super::AppleSignedIn;

/// Asks for a challenge, stores its `state` in the cookie the callback checks
/// (the callback is a cross-site post, so the cookie must be `SameSite=None`),
/// then hands the page to Apple. In redirect mode Apple posts the result
/// straight to the callback and the browser follows the server's redirect, so
/// nothing here sees it.
const WEB_SCRIPT: &str = r#"
(async () => {
    const response = await fetch("/api/v1/apple_signin_prepare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ native: false, return_to: __RETURN_TO__ }),
    });
    if (!response.ok) {
        throw new Error("Sign in with Apple is not available (" + response.status + ")");
    }
    const challenge = await response.json();
    document.cookie = "apple_state=" + challenge.state + "; Max-Age=600; Path=/; Secure; SameSite=None";
    if (!window.AppleID) {
        await new Promise((resolve, reject) => {
            const script = document.createElement("script");
            script.src = "https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js";
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }
    AppleID.auth.init({
        clientId: challenge.services_id,
        scope: "name email",
        redirectURI: challenge.redirect_uri,
        state: challenge.state,
        nonce: challenge.nonce,
        usePopup: false,
    });
    await AppleID.auth.signIn();
})().catch((error) => console.error("[g3-auth] Sign in with Apple failed", error));
"#;

/// The script with the visitor's `return_to` (JSON-encoded, so it is a string
/// literal and nothing else) in place.
#[cfg(not(target_os = "ios"))]
fn web_script(return_to: Option<&str>) -> String {
    WEB_SCRIPT.replace("__RETURN_TO__", &serde_json::json!(return_to).to_string())
}

/// Apple's mark, in the button's text color as their guidelines allow.
fn apple_logo() -> Element {
    rsx! {
        svg {
            xmlns: "http://www.w3.org/2000/svg",
            view_box: "0 0 814 1000",
            width: "16",
            height: "18",
            fill: "currentColor",
            "aria-hidden": "true",
            path { d: "M788 341c-6 5-111 64-111 195 0 152 133 206 137 207-1 3-21 74-70 146-44 63-90 126-160 126s-88-41-169-41c-79 0-107 42-171 42s-109-58-160-130C58 782 0 654 0 532c0-196 127-300 253-300 67 0 123 44 165 44 40 0 102-47 178-47 29 0 133 3 192 112zM555 164c32-37 54-89 54-140 0-7-1-14-2-20-51 2-112 34-149 77-29 33-56 85-56 137 0 8 1 16 2 18 3 1 9 1 14 1 46 0 104-31 137-73z" }
        }
    }
}

/// The client for the iOS sheet: ask the server for a challenge, show the
/// sheet, post what it returns.
#[cfg(target_os = "ios")]
async fn native_sign_in(
    plugins: &mut g3_native_plugins::NativePlugins,
    return_to: Option<String>,
) -> Result<AppleSignedIn, String> {
    let client = dioxus::fullstack::GLOBAL_REQUEST_CLIENT
        .get()
        .ok_or_else(|| "The Apple sign-in client is unavailable.".to_string())?;
    let base = dioxus::fullstack::get_server_url();

    let challenge: super::AppleChallenge = client
        .post(format!("{base}{}", super::APPLE_PREPARE_PATH))
        .json(&super::ApplePrepare {
            native: true,
            return_to,
        })
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?
        .json()
        .await
        .map_err(|error| error.to_string())?;

    plugins
        .auth
        .write()
        .start_apple_auth(&challenge.state, &challenge.nonce)?;
    let start = std::time::Instant::now();
    let credential = loop {
        if start.elapsed() >= std::time::Duration::from_secs(120) {
            return Err("Sign in with Apple timed out.".to_string());
        }
        if !plugins.auth.write().is_auth_awaiting() {
            break plugins
                .auth
                .write()
                .poll_auth_result()?
                .ok_or_else(|| "Sign in with Apple was cancelled.".to_string())?;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };

    let response = client
        .post(format!("{base}{}", super::APPLE_CALLBACK_PATH))
        .header("accept", "application/json")
        .form(&[("credential", credential)])
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err("Sign in with Apple could not be completed.".to_string());
    }
    let body = response.text().await.map_err(|error| error.to_string())?;
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

/// "Sign in with Apple", on the web and iOS. Put it where the button goes.
///
/// - **Web:** the button starts Apple's redirect flow; the browser is
///   redirected by the server once the token is checked, so there is nothing
///   to handle.
/// - **iOS:** the system sheet, then `on_signed_in` is called with where the
///   server would have sent the browser (it navigates there by default).
/// - **No Services ID configured**, or a platform with no flow: a disabled
///   button, so the screen keeps its shape.
///
/// The server half is [`apple_router`](super::apple_router).
#[component]
pub fn AppleSignIn(
    /// The web Services ID. Defaults to `APPLE_SERVICES_ID` as it was when
    /// g3-auth was built ([`services_id`](super::services_id)); pass the app's
    /// own when a build script, not the environment, supplies it.
    services_id: Option<String>,
    /// Called after a native sign-in with the path to show next. Defaults to
    /// navigating there. Never called on the web.
    on_signed_in: Option<EventHandler<AppleSignedIn>>,
    /// Where the visitor was headed, passed to
    /// [`AppleAccounts::destination`](super::AppleAccounts::destination) when the
    /// attempt finishes. The server keeps it for ten minutes.
    return_to: Option<String>,
    /// Button text. Defaults to "Sign in with Apple".
    label: Option<String>,
    /// Disable the button, for another sign-in in progress.
    disabled: Option<bool>,
) -> Element {
    let label = label.unwrap_or_else(|| "Sign in with Apple".to_string());
    let disabled = disabled.unwrap_or(false);

    let mut error = use_signal(|| None::<String>);
    let mut pending = use_signal(|| false);
    #[cfg(target_os = "ios")]
    let plugins = use_context::<g3_native_plugins::NativePlugins>();

    let configured = services_id.is_some() || super::services_id().is_some();
    let on_click = move |_| {
        error.set(None);
        #[cfg(target_os = "ios")]
        {
            pending.set(true);
            let mut plugins = plugins;
            spawn(async move {
                match native_sign_in(&mut plugins, return_to.clone()).await {
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
        #[cfg(not(target_os = "ios"))]
        {
            let _ = (&on_signed_in, &mut pending);
            let _ = document::eval(&web_script(return_to.as_deref()));
        }
    };

    rsx! {
        Button {
            fill: ButtonFill::Outline,
            color: Color::Neutral,
            expand: ButtonExpand::Block,
            disabled: !configured || disabled || pending(),
            start: apple_logo(),
            onclick: on_click,
            "{label}"
        }
        if let Some(message) = error() {
            Text { variant: TextVariant::Caption, color: Color::Danger, "{message}" }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_web_script_keeps_the_state_cookie_the_callback_checks() {
        // The server rejects a browser post without this exact cookie.
        assert!(super::WEB_SCRIPT.contains("apple_state="));
        assert!(super::WEB_SCRIPT.contains("SameSite=None"));
        assert!(super::WEB_SCRIPT.contains("usePopup: false"));
        assert!(super::WEB_SCRIPT.contains(super::super::APPLE_PREPARE_PATH));
    }

    #[cfg(not(target_os = "ios"))]
    #[test]
    fn return_to_reaches_the_script_as_a_json_string_and_nothing_else() {
        let script = super::web_script(Some(r#"/g"; alert(1); "#));
        assert!(script.contains(r#"return_to: "/g\"; alert(1); ""#));
        assert!(!script.contains("__RETURN_TO__"));
        assert!(super::web_script(None).contains("return_to: null"));
    }
}
