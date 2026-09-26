use std::sync::Arc;

use async_trait::async_trait;
use axum_session::{DatabaseError, DatabasePool};
use chrono::Utc;
use surrealdb::{Connection, Surreal};
use surrealdb_types::{SurrealValue, Table, Value};

#[derive(SurrealValue)]
struct StoredSession {
    sessionstore: String,
    sessionexpires: String,
    sessionid: String,
}

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
}

impl<C> SurrealSessionPool<C>
where
    C: Connection,
{
    /// A pool over the app's shared database handle.
    pub fn new(connection: Arc<Surreal<C>>) -> Self {
        Self { connection }
    }
}

// By hand: deriving would demand `C: Clone + Debug`, which connection
// engine types needn't be, while an `Arc` clones regardless.
impl<C: Connection> Clone for SurrealSessionPool<C> {
    fn clone(&self) -> Self {
        Self {
            connection: Arc::clone(&self.connection),
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
        let _: Option<Value> = self
            .connection
            .upsert((table_name, id))
            .content(StoredSession {
                sessionstore: session.to_string(),
                sessionexpires: expires.to_string(),
                sessionid: id.to_string(),
            })
            .await
            .map_err(|error| DatabaseError::GenericInsertError(error.to_string()))?;

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
