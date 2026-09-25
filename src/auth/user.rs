use std::{fmt, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use axum_session_auth::Authentication;
use surrealdb::{Connection, Surreal};
use surrealdb_types::{RecordId, SurrealValue, ToSql};

use super::SurrealSessionPool;

/// Describes where an app keeps its accounts, so [`SessionUser`] can load
/// one. Implement it on a marker type:
///
/// ```ignore
/// pub enum AppUser {}
///
/// impl AuthUser for AppUser {
///     // Keep a deleted account's leftover row from staying signed in.
///     const FILTER: Option<&'static str> = Some("deleted_at = NONE");
/// }
/// ```
pub trait AuthUser: Send + Sync + 'static {
    /// The table holding accounts. A session stores the record's key.
    const TABLE: &'static str = "user";
    /// The field shown as the signed-in user's name.
    const NAME_FIELD: &'static str = "display_name";
    /// An extra SurrealQL condition an account must meet to load, such as
    /// `deleted_at = NONE`. An account failing it is signed out.
    const FILTER: Option<&'static str> = None;
}

/// The signed-in user, as the auth session sees them. A request with no
/// usable session gets [`SessionUser::anonymous`].
pub struct SessionUser<U> {
    /// The account record's key, e.g. `k3j2h1` for `user:k3j2h1`. Empty
    /// when anonymous.
    pub id: String,
    /// Whether nobody is signed in.
    pub anonymous: bool,
    /// The account's [`AuthUser::NAME_FIELD`].
    pub username: String,
    user: PhantomData<fn() -> U>,
}

impl<U> SessionUser<U> {
    /// A signed-in user.
    pub fn signed_in(id: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            anonymous: false,
            username: username.into(),
            user: PhantomData,
        }
    }

    /// Nobody signed in.
    pub fn anonymous() -> Self {
        Self {
            id: String::new(),
            anonymous: true,
            username: String::new(),
            user: PhantomData,
        }
    }
}

impl<U: AuthUser> SessionUser<U> {
    /// The account's record id: [`AuthUser::TABLE`] and [`id`](Self::id).
    pub fn record_id(&self) -> RecordId {
        RecordId::new(U::TABLE, self.id.clone())
    }
}

/// Anonymous, **not** a signed-in user with an empty id: the default is
/// what a request with no usable session gets, so deriving it (which would
/// give `anonymous: false`) would wave every signed-out visitor through an
/// `anonymous` check.
impl<U> Default for SessionUser<U> {
    fn default() -> Self {
        Self::anonymous()
    }
}

impl<U> Clone for SessionUser<U> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            anonymous: self.anonymous,
            username: self.username.clone(),
            user: PhantomData,
        }
    }
}

impl<U> fmt::Debug for SessionUser<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionUser")
            .field("id", &self.id)
            .field("anonymous", &self.anonymous)
            .field("username", &self.username)
            .finish()
    }
}

#[derive(SurrealValue)]
struct LoadedUser {
    id: RecordId,
    username: Option<String>,
}

#[async_trait]
impl<U, C> Authentication<SessionUser<U>, String, Arc<Surreal<C>>> for SessionUser<U>
where
    U: AuthUser,
    C: Connection,
{
    async fn load_user(
        userid: String,
        db: Option<&Arc<Surreal<C>>>,
    ) -> anyhow::Result<SessionUser<U>> {
        let db = db.ok_or_else(|| anyhow::anyhow!("Database connection not provided"))?;
        let filter = U::FILTER
            .map(|filter| format!(" WHERE {filter}"))
            .unwrap_or_default();
        let user = db
            .query(format!(
                "SELECT id, {name} AS username FROM $record{filter}",
                name = U::NAME_FIELD,
            ))
            .bind(("record", RecordId::new(U::TABLE, userid)))
            .await?
            .take::<Option<LoadedUser>>(0)?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        Ok(SessionUser::signed_in(
            user.id.key.to_sql(),
            user.username.unwrap_or_default(),
        ))
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

/// The auth session a request carries, as `axum_session_auth` resolves it.
pub type AuthSession<U, C> =
    axum_session_auth::AuthSession<SessionUser<U>, String, SurrealSessionPool<C>, Arc<Surreal<C>>>;

/// The layer that resolves [`AuthSession`], with the database handle it
/// loads users from.
pub type AuthSessionLayer<U, C> = axum_session_auth::AuthSessionLayer<
    SessionUser<U>,
    String,
    SurrealSessionPool<C>,
    Arc<Surreal<C>>,
>;

/// An extractor bundling what most server functions need: the database,
/// the auth session (to sign in or out), and the resolved user.
///
/// The database comes from an `Extension(Arc<Surreal<C>>)` on the router.
/// Alias it once in the app:
///
/// ```ignore
/// pub type SessionContext = g3_core::auth::SessionContext<AppUser, Client>;
///
/// #[get("/api/v1/user", SessionContext { db, session_user, .. }: SessionContext)]
/// ```
pub struct SessionContext<U: AuthUser, C: Connection> {
    /// The shared database handle.
    pub db: Arc<Surreal<C>>,
    /// The raw auth session, for `login_user` and `logout_user`.
    pub auth_session: AuthSession<U, C>,
    /// The signed-in user, or [`SessionUser::anonymous`].
    pub session_user: SessionUser<U>,
}

impl<S, U, C> FromRequestParts<S> for SessionContext<U, C>
where
    S: Send + Sync,
    U: AuthUser,
    C: Connection,
{
    // Not `()`: axum renders that as an empty 200, which the server function
    // client reads as `null`, so a missing layer would reach the app as an
    // ordinary answer ("nobody is signed in"). A misconfigured stack has to
    // look like the server fault it is.
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let db = parts
            .extensions
            .get::<Arc<Surreal<C>>>()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database missing. Is `Extension(Arc<Surreal<_>>)` on the router?",
            ))?
            .clone();
        let auth_session = parts
            .extensions
            .get::<AuthSession<U, C>>()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Auth session missing. Is `AuthSessionLayer` installed?",
            ))?
            .clone();
        let session_user = auth_session.current_user.clone().unwrap_or_default();

        Ok(Self {
            db,
            auth_session,
            session_user,
        })
    }
}
