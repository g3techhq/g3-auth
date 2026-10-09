//! What an email and a password must look like, and the words for refusing them.
//!
//! Plain functions with no feature and no I/O, so a form can check what the
//! server will check and show the same message. The server still calls them:
//! the client's check is a courtesy, not a control.
//!
//! Hashing and comparing a password is the database's job, in the app's own
//! queries (`crypto::argon2::generate` and `crypto::argon2::compare`), so a
//! hash never passes through application code.

/// The email is not an address.
pub const INVALID_EMAIL: &str = "Enter a valid email address.";
/// The password is outside [`PASSWORD_LENGTH`].
pub const INVALID_PASSWORD_LENGTH: &str = "Password must be between 8 and 128 characters.";
/// The confirmation differs from the password.
pub const PASSWORDS_DO_NOT_MATCH: &str = "Passwords do not match.";
/// Sign-in failed. One message for an unknown email and a wrong password, so the
/// answer does not say which emails have accounts.
pub const INVALID_CREDENTIALS: &str = "Invalid email or password.";
/// The email belongs to an account that signs in with a password.
pub const ACCOUNT_EXISTS: &str = "Account already exists.";
/// The email belongs to an account that signs in with Google.
pub const GOOGLE_ACCOUNT_EXISTS: &str = "Sign in with Google.";
/// The email belongs to an account that signs in with Apple.
pub const APPLE_ACCOUNT_EXISTS: &str = "Sign in with Apple.";

/// The characters a password may have, counted as characters and not bytes.
pub const PASSWORD_LENGTH: std::ops::RangeInclusive<usize> = 8..=128;

/// The form an email is stored and looked up in.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Whether `email` (already [`normalize_email`]d) is plausibly an address: one
/// `@`, a local part, a dotted domain, no whitespace. Not a deliverability check.
pub fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.is_empty() || email.len() > 254 || email.chars().any(char::is_whitespace) {
        return Err(INVALID_EMAIL);
    }

    let mut parts = email.split('@');
    let (Some(local), Some(domain)) = (parts.next(), parts.next()) else {
        return Err(INVALID_EMAIL);
    };

    if parts.next().is_some()
        || local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(INVALID_EMAIL);
    }

    Ok(())
}

/// Whether `password` has an allowed length. Nothing else is required: length
/// is what resists guessing, and a composition rule only teaches `Password1!`.
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if PASSWORD_LENGTH.contains(&password.chars().count()) {
        Ok(())
    } else {
        Err(INVALID_PASSWORD_LENGTH)
    }
}

/// Checks a sign-up and returns the normalized email to store.
pub fn validate_signup(
    email: &str,
    password: &str,
    confirmation: &str,
) -> Result<String, &'static str> {
    let email = normalize_email(email);
    validate_email(&email)?;
    validate_password(password)?;

    if password != confirmation {
        return Err(PASSWORDS_DO_NOT_MATCH);
    }

    Ok(email)
}

/// What to tell someone who signs up with an email that already has an account,
/// pointing them at the way they signed in. A provider outranks a password, and
/// Google outranks Apple, for an account that has several.
pub fn existing_account_message(google: bool, apple: bool) -> &'static str {
    if google {
        GOOGLE_ACCOUNT_EXISTS
    } else if apple {
        APPLE_ACCOUNT_EXISTS
    } else {
        ACCOUNT_EXISTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_stored_trimmed_and_lowercase() {
        assert_eq!(
            normalize_email("  Golfer@Example.COM "),
            "golfer@example.com"
        );
    }

    #[test]
    fn a_well_formed_email_passes() {
        assert_eq!(validate_email("golfer@example.com"), Ok(()));
        assert_eq!(validate_email("a.b+c@sub.example.co"), Ok(()));
    }

    #[test]
    fn malformed_emails_are_refused() {
        for bad in [
            "",
            "golfer",
            "golfer@",
            "@example.com",
            "golfer@example",
            "golfer@.example.com",
            "golfer@example.com.",
            "gol fer@example.com",
            "a@b@example.com",
        ] {
            assert_eq!(validate_email(bad), Err(INVALID_EMAIL), "{bad:?}");
        }
        assert_eq!(
            validate_email(&format!("{}@example.com", "a".repeat(65))),
            Err(INVALID_EMAIL)
        );
        assert_eq!(
            validate_email(&format!("a@{}.com", "b".repeat(250))),
            Err(INVALID_EMAIL)
        );
    }

    #[test]
    fn password_length_counts_characters_not_bytes() {
        assert_eq!(validate_password("short"), Err(INVALID_PASSWORD_LENGTH));
        assert_eq!(validate_password("exactly8"), Ok(()));
        assert_eq!(validate_password(&"x".repeat(128)), Ok(()));
        assert_eq!(
            validate_password(&"x".repeat(129)),
            Err(INVALID_PASSWORD_LENGTH)
        );
        // Eight characters, sixteen bytes.
        assert_eq!(validate_password("éééééééé"), Ok(()));
    }

    #[test]
    fn a_signup_returns_the_normalized_email_or_the_first_problem() {
        assert_eq!(
            validate_signup(" A@B.co ", "password1", "password1"),
            Ok("a@b.co".into())
        );
        assert_eq!(
            validate_signup("nope", "password1", "password1"),
            Err(INVALID_EMAIL)
        );
        assert_eq!(
            validate_signup("a@b.co", "short", "short"),
            Err(INVALID_PASSWORD_LENGTH)
        );
        assert_eq!(
            validate_signup("a@b.co", "password1", "password2"),
            Err(PASSWORDS_DO_NOT_MATCH)
        );
    }

    #[test]
    fn an_existing_account_points_at_how_it_signs_in() {
        assert_eq!(existing_account_message(false, false), ACCOUNT_EXISTS);
        assert_eq!(existing_account_message(true, false), GOOGLE_ACCOUNT_EXISTS);
        assert_eq!(existing_account_message(false, true), APPLE_ACCOUNT_EXISTS);
        assert_eq!(existing_account_message(true, true), GOOGLE_ACCOUNT_EXISTS);
    }
}
