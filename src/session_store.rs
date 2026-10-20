use std::sync::Arc;

use async_trait::async_trait;
use axum_session::{DatabaseError, DatabasePool};
use chrono::Utc;
use surrealdb::{Connection, Surreal};
use surrealdb_types::{RecordId, SurrealValue, Table, ToSql, Value};

#[derive(SurrealValue)]
struct StoredSession {
    sessionstore: String,
    sessionexpires: String,
    sessionid: String,
}

#[derive(SurrealValue)]
struct TrackedSession {
    sessionstore: String,
    sessionexpires: String,
    sessionid: String,
    session_account: Option<RecordId>,
    account_indexed: bool,
}

#[derive(Clone, Copy)]
struct AccountTracking {
    table: &'static str,
    key: &'static str,
}

#[derive(SurrealValue)]
struct LegacySession {
    id: RecordId,
    sessionid: String,
    sessionstore: String,
}

fn subject(session: &str, tracking: AccountTracking) -> Result<Option<RecordId>, DatabaseError> {
    let value: serde_json::Value = serde_json::from_str(session).map_err(|_| {
        DatabaseError::GenericNotSupportedError(
            "Account tracking requires unencrypted axum_session JSON".into(),
        )
    })?;
    let data = value
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            DatabaseError::GenericNotSupportedError("Unknown axum_session data format".into())
        })?;
    let Some(encoded) = data.get(tracking.key) else {
        return Ok(None);
    };
    let id = encoded
        .as_str()
        .and_then(|encoded| serde_json::from_str::<String>(encoded).ok())
        .ok_or_else(|| {
            DatabaseError::GenericNotSupportedError(
                "Account tracking requires String auth identifiers".into(),
            )
        })?;
    Ok((!id.is_empty()).then(|| RecordId::new(tracking.table, id)))
}

fn fence(account: &RecordId) -> RecordId {
    // Bound as a typed record key, never parsed as SQL. Table and key types
    // remain distinct even when two account tables use the same plain key.
    RecordId::new("auth_session_subject", account.to_sql())
}

const TRACKED_STORE: &str = r#"
BEGIN TRANSACTION;
UPSERT $fence SET account = $account, retired = retired ?? false, touched_at = time::now();
LET $retired = (SELECT VALUE retired FROM ONLY $fence);
LET $live = (SELECT VALUE id FROM $account);
IF $retired OR array::len($live) = 0 {
    UPDATE $fence SET retired = true;
    DELETE $table WHERE session_account = $account OR sessionid = $session_id;
} ELSE {
    UPSERT $session_record CONTENT $content;
};
COMMIT TRANSACTION;
"#;

/// Adapts axum_session's `DatabasePool` trait to SurrealDB v3, storing
/// sessions in the plain `sessions` table (no off-the-shelf SurrealDB
/// adapter exists for this axum_session version).
///
/// Define the table with [`SESSIONS_SCHEMA`](super::SESSIONS_SCHEMA).
///
/// ```ignore
/// let store = SessionStore::new(Some(SurrealSessionPool::new(Arc::clone(&db))), config).await?;
/// ```
pub struct SurrealSessionPool<C>
where
    C: Connection,
{
    connection: Arc<Surreal<C>>,
    account_tracking: Option<AccountTracking>,
}

impl<C> SurrealSessionPool<C>
where
    C: Connection,
{
    /// A pool over the app's shared database handle.
    pub fn new(connection: Arc<Surreal<C>>) -> Self {
        Self {
            connection,
            account_tracking: None,
        }
    }

    /// Track String account identifiers stored by axum_session_auth's default
    /// `user_auth_session_id` key. Apply the current SESSIONS_SCHEMA first.
    /// This mode requires unencrypted axum_session JSON at the adapter boundary;
    /// do not combine it with `SessionConfig::with_database_key`.
    ///
    /// Also set `AuthConfig::default().set_cache(false)` so another device
    /// cannot authenticate from an old cached account after retirement.
    pub fn track_accounts<U: super::AuthUser>(self) -> Self {
        self.track_accounts_with_key::<U>("user_auth_session_id")
    }

    /// Account tracking for an app using `AuthConfig::with_session_id`.
    /// `key` must be the same source-defined key passed to that configuration.
    pub fn track_accounts_with_key<U: super::AuthUser>(mut self, key: &'static str) -> Self {
        self.account_tracking = Some(AccountTracking {
            table: U::TABLE,
            key,
        });
        self
    }

    /// Index existing plaintext sessions without changing payloads or expiry.
    /// Concurrent rewrites are not assigned another account: each update checks
    /// the exact payload read. Retire old, untracked writers before relying on it.
    /// Unknown/encrypted legacy formats fail instead of claiming full coverage.
    pub async fn index_account_sessions(&self, table_name: &str) -> Result<(), DatabaseError> {
        let tracking = self.account_tracking.ok_or_else(|| {
            DatabaseError::GenericNotSupportedError("Account tracking is not enabled".into())
        })?;
        let mut after = None::<RecordId>;
        loop {
            let mut response = self.connection.query("SELECT id, sessionid, sessionstore FROM $table WHERE account_indexed != true AND ($after = NONE OR id > $after) ORDER BY id LIMIT 128")
                .bind(("table", Table::from(table_name))).bind(("after", after.clone())).await
                .and_then(|response| response.check())
                .map_err(|_| DatabaseError::GenericSelectError("Could not read legacy account sessions".into()))?;
            let rows: Vec<LegacySession> = response.take(0).map_err(|_| {
                DatabaseError::GenericSelectError("Could not decode legacy account sessions".into())
            })?;
            let full = rows.len() == 128;
            for row in rows {
                let account = subject(&row.sessionstore, tracking)?;
                self.connection.query("UPDATE $record SET session_account = $account, account_indexed = true WHERE sessionstore = $previous AND sessionid = $session_id")
                    .bind(("record", row.id.clone())).bind(("account", account)).bind(("previous", row.sessionstore)).bind(("session_id", row.sessionid))
                    .await.and_then(|response| response.check())
                    .map_err(|_| DatabaseError::GenericInsertError("Could not index legacy account sessions".into()))?;
                after = Some(row.id);
            }
            if !full {
                break;
            }
        }
        let mut response = self
            .connection
            .query("RETURN count(SELECT id FROM $table WHERE account_indexed != true);")
            .bind(("table", Table::from(table_name)))
            .await
            .and_then(|response| response.check())
            .map_err(|_| {
                DatabaseError::GenericSelectError(
                    "Could not verify legacy account session indexing".into(),
                )
            })?;
        let remaining: Option<i64> = response.take(0).map_err(|_| {
            DatabaseError::GenericSelectError(
                "Could not verify legacy account session indexing".into(),
            )
        })?;
        if remaining != Some(0) {
            return Err(DatabaseError::GenericNotSupportedError(
                "Unindexed sessions remain; apply the current schema and retire untracked writers"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Permanently retire a non-reused account identity and remove its stored
    /// sessions, including legacy payloads after indexing. Delayed stores touch
    /// the same fence transactionally and cannot recreate retired sessions.
    ///
    /// This is for account erasure, not ordinary sign-out or password changes.
    /// It does not remove the account/content, invalidate other process caches,
    /// or revoke provider grants. Keep failures pending and verify those steps
    /// separately. Retain the private retirement fence across supported restores;
    /// do not roll back to an untracked writer while relying on this guarantee.
    pub async fn retire_account_sessions(
        &self,
        table_name: &str,
        account: &RecordId,
    ) -> Result<(), DatabaseError> {
        let tracking = self.account_tracking.ok_or_else(|| {
            DatabaseError::GenericNotSupportedError("Account tracking is not enabled".into())
        })?;
        if account.table.as_str() != tracking.table {
            return Err(DatabaseError::GenericNotSupportedError(
                "Account table does not match the tracked identity".into(),
            ));
        }
        // Retire first: even an indexing failure must not let delayed tracked
        // responses reintroduce this account's data while cleanup is retried.
        self.connection.query("BEGIN TRANSACTION; UPSERT $fence SET account = $account, retired = true, touched_at = time::now(); DELETE $table WHERE session_account = $account; COMMIT TRANSACTION;")
            .bind(("fence", fence(account))).bind(("account", account.clone())).bind(("table", Table::from(table_name)))
            .await.and_then(|response| response.check())
            .map_err(|_| DatabaseError::GenericDeleteError("Could not retire account sessions".into()))?;
        self.index_account_sessions(table_name).await?;
        self.connection.query("BEGIN TRANSACTION; UPDATE $fence SET touched_at = time::now(); DELETE $table WHERE session_account = $account; COMMIT TRANSACTION;")
            .bind(("fence", fence(account))).bind(("account", account.clone())).bind(("table", Table::from(table_name)))
            .await.and_then(|response| response.check())
            .map_err(|_| DatabaseError::GenericDeleteError("Could not verify account session removal".into()))?;
        let mut response = self
            .connection
            .query("RETURN count(SELECT id FROM $table WHERE session_account = $account);")
            .bind(("account", account.clone()))
            .bind(("table", Table::from(table_name)))
            .await
            .and_then(|response| response.check())
            .map_err(|_| {
                DatabaseError::GenericSelectError("Could not verify account session removal".into())
            })?;
        let remaining: Option<i64> = response.take(0).map_err(|_| {
            DatabaseError::GenericSelectError("Could not verify account session removal".into())
        })?;
        if remaining != Some(0) {
            return Err(DatabaseError::GenericDeleteError(
                "Account sessions remain pending removal".into(),
            ));
        }
        let retired: Option<bool> = self
            .connection
            .query("SELECT VALUE retired FROM ONLY $fence")
            .bind(("fence", fence(account)))
            .await
            .and_then(|response| response.check())
            .map_err(|_| {
                DatabaseError::GenericSelectError(
                    "Could not verify account retirement fence".into(),
                )
            })?
            .take(0)
            .map_err(|_| {
                DatabaseError::GenericSelectError(
                    "Could not verify account retirement fence".into(),
                )
            })?;
        if retired != Some(true) {
            return Err(DatabaseError::GenericNotSupportedError(
                "Account retirement schema is missing or incompatible".into(),
            ));
        }
        Ok(())
    }
}

// By hand: deriving would demand `C: Clone + Debug`, which connection
// engine types needn't be, while an `Arc` clones regardless.
impl<C: Connection> Clone for SurrealSessionPool<C> {
    fn clone(&self) -> Self {
        Self {
            connection: Arc::clone(&self.connection),
            account_tracking: self.account_tracking,
        }
    }
}

impl<C: Connection> std::fmt::Debug for SurrealSessionPool<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealSessionPool").finish_non_exhaustive()
    }
}

#[async_trait]
impl<C> DatabasePool for SurrealSessionPool<C>
where
    C: Connection,
{
    async fn initiate(&self, _table_name: &str) -> Result<(), DatabaseError> {
        Ok(())
    }

    // Not `SELECT VALUE count() .. GROUP ALL`: SurrealDB 3 answers that with
    // an object rather than the number, so every count failed to decode.
    async fn count(&self, table_name: &str) -> Result<i64, DatabaseError> {
        let mut response = self
            .connection
            .query("RETURN count(SELECT id FROM $table_name)")
            .bind(("table_name", Table::from(table_name)))
            .await
            .map_err(|error| DatabaseError::GenericSelectError(error.to_string()))?;

        Ok(response
            .take::<Option<i64>>(0)
            .map_err(|error| DatabaseError::GenericNotSupportedError(error.to_string()))?
            .unwrap_or_default())
    }

    async fn store(
        &self,
        id: &str,
        session: &str,
        expires: i64,
        table_name: &str,
    ) -> Result<(), DatabaseError> {
        let Some(tracking) = self.account_tracking else {
            // Default pools keep the original write shape and remain usable
            // before an app rolls out the opt-in tracking schema.
            let _: Option<Value> = self
                .connection
                .upsert((table_name, id))
                .content(StoredSession {
                    sessionstore: session.to_string(),
                    sessionexpires: expires.to_string(),
                    sessionid: id.to_string(),
                })
                .await
                .map_err(|_| {
                    DatabaseError::GenericInsertError("Could not persist a session".into())
                })?;
            return Ok(());
        };
        let account = subject(session, tracking)?;
        let content = TrackedSession {
            sessionstore: session.to_string(),
            sessionexpires: expires.to_string(),
            sessionid: id.to_string(),
            session_account: account.clone(),
            account_indexed: true,
        };
        if let Some(account) = account {
            self.connection
                .query(TRACKED_STORE)
                .bind(("fence", fence(&account)))
                .bind(("account", account))
                .bind(("table", Table::from(table_name)))
                .bind(("session_id", id.to_string()))
                .bind(("session_record", RecordId::new(table_name, id)))
                .bind(("content", content))
                .await
                .and_then(|response| response.check())
                .map_err(|_| {
                    DatabaseError::GenericInsertError(
                        "Could not persist a tracked account session".into(),
                    )
                })?;
        } else {
            let _: Option<Value> = self
                .connection
                .upsert((table_name, id))
                .content(content)
                .await
                .map_err(|_| {
                    DatabaseError::GenericInsertError("Could not persist a session".into())
                })?;
        }

        Ok(())
    }

    async fn load(&self, id: &str, table_name: &str) -> Result<Option<String>, DatabaseError> {
        let mut response = self
            .connection
            .query(
                r#"
                    SELECT VALUE sessionstore
                    FROM $table_name
                    WHERE sessionid = $session_id
                        AND (
                            sessionexpires = NONE
                            OR type::number(sessionexpires) > $expires
                        )
                    LIMIT 1
                "#,
            )
            .bind(("table_name", Table::from(table_name)))
            .bind(("session_id", id.to_string()))
            .bind(("expires", Utc::now().timestamp()))
            .await
            .map_err(|error| DatabaseError::GenericSelectError(error.to_string()))?;

        response
            .take::<Option<String>>(0)
            .map_err(|error| DatabaseError::GenericNotSupportedError(error.to_string()))
    }

    async fn delete_one_by_id(&self, id: &str, table_name: &str) -> Result<(), DatabaseError> {
        self.connection
            .query("DELETE $table_name WHERE sessionid = $session_id")
            .bind(("table_name", Table::from(table_name)))
            .bind(("session_id", id.to_string()))
            .await
            .map_err(|error| DatabaseError::GenericDeleteError(error.to_string()))?;

        Ok(())
    }

    async fn exists(&self, id: &str, table_name: &str) -> Result<bool, DatabaseError> {
        let mut response = self
            .connection
            .query(
                r#"
                    SELECT VALUE sessionid
                    FROM $table_name
                    WHERE sessionid = $session_id
                        AND (
                            sessionexpires = NONE
                            OR type::number(sessionexpires) > $expires
                        )
                    LIMIT 1
                "#,
            )
            .bind(("table_name", Table::from(table_name)))
            .bind(("session_id", id.to_string()))
            .bind(("expires", Utc::now().timestamp()))
            .await
            .map_err(|error| DatabaseError::GenericSelectError(error.to_string()))?;

        let session_id = response
            .take::<Option<String>>(0)
            .map_err(|error| DatabaseError::GenericNotSupportedError(error.to_string()))?;

        Ok(session_id.is_some())
    }

    async fn delete_by_expiry(&self, table_name: &str) -> Result<Vec<String>, DatabaseError> {
        let mut response = self
            .connection
            .query(
                r#"
                    DELETE $table_name
                    WHERE sessionexpires != NONE
                        AND type::number(sessionexpires) < $expires
                    RETURN BEFORE
                "#,
            )
            .bind(("table_name", Table::from(table_name)))
            .bind(("expires", Utc::now().timestamp()))
            .await
            .map_err(|error| DatabaseError::GenericDeleteError(error.to_string()))?;

        response
            .take::<Vec<String>>("sessionid")
            .map_err(|error| DatabaseError::GenericSelectError(error.to_string()))
    }

    async fn delete_all(&self, table_name: &str) -> Result<(), DatabaseError> {
        self.connection
            .query("DELETE $table_name")
            .bind(("table_name", Table::from(table_name)))
            .await
            .map_err(|error| DatabaseError::GenericDeleteError(error.to_string()))?;

        Ok(())
    }

    async fn get_ids(&self, table_name: &str) -> Result<Vec<String>, DatabaseError> {
        let mut response = self
            .connection
            .query(
                r#"
                    SELECT VALUE sessionid
                    FROM $table_name
                    WHERE sessionexpires = NONE
                        OR type::number(sessionexpires) > $expires
                "#,
            )
            .bind(("table_name", Table::from(table_name)))
            .bind(("expires", Utc::now().timestamp()))
            .await
            .map_err(|error| DatabaseError::GenericSelectError(error.to_string()))?;

        response
            .take::<Vec<String>>(0)
            .map_err(|error| DatabaseError::GenericNotSupportedError(error.to_string()))
    }

    fn auto_handles_expiry(&self) -> bool {
        false
    }
}
