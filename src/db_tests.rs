//! Against a real (in-memory) SurrealDB: the queries are strings, so only
//! running them proves they work.

use std::sync::Arc;

use axum_session::DatabasePool;
use axum_session_auth::Authentication;
use surrealdb::{
    Surreal,
    engine::local::{Db, Mem},
};

use surrealdb_types::RecordId;

use super::{AuthUser, SESSIONS_SCHEMA, SessionUser, SurrealSessionPool};

async fn database() -> Arc<Surreal<Db>> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory database");
    db.use_ns("test").use_db("test").await.expect("namespace");
    db.query(SESSIONS_SCHEMA)
        .await
        .expect("schema")
        .check()
        .expect("schema applies");
    db.query(
        "CREATE user:ann SET display_name = 'Ann';
         CREATE user:gone SET display_name = 'Gone', deleted_at = time::now();
         CREATE user:nameless;
         CREATE member:bo SET name = 'Bo';",
    )
    .await
    .expect("users")
    .check()
    .expect("users created");
    Arc::new(db)
}

enum DefaultUser {}
impl AuthUser for DefaultUser {}

enum LiveUser {}
impl AuthUser for LiveUser {
    const FILTER: Option<&'static str> = Some("deleted_at = NONE");
}

enum Member {}
impl AuthUser for Member {
    const TABLE: &'static str = "member";
    const NAME_FIELD: &'static str = "name";
}

async fn load<U: AuthUser>(db: &Arc<Surreal<Db>>, id: &str) -> anyhow::Result<SessionUser<U>> {
    <SessionUser<U> as Authentication<_, _, Arc<Surreal<Db>>>>::load_user(id.to_string(), Some(db))
        .await
}

#[tokio::test]
async fn loads_a_signed_in_user() {
    let db = database().await;
    let user = load::<DefaultUser>(&db, "ann").await.expect("ann loads");
    assert_eq!(user.id, "ann");
    assert_eq!(user.username, "Ann");
    assert!(!user.anonymous);
    assert_eq!(user.record_id(), RecordId::new("user", "ann"));
}

#[tokio::test]
async fn a_missing_account_does_not_load() {
    let db = database().await;
    assert!(load::<DefaultUser>(&db, "nobody").await.is_err());
}

#[tokio::test]
async fn the_filter_signs_out_accounts_that_fail_it() {
    let db = database().await;
    assert!(load::<DefaultUser>(&db, "gone").await.is_ok());
    assert!(load::<LiveUser>(&db, "gone").await.is_err());
    assert!(load::<LiveUser>(&db, "ann").await.is_ok());
}

#[tokio::test]
async fn a_missing_name_still_signs_in() {
    let db = database().await;
    let user = load::<DefaultUser>(&db, "nameless").await.expect("loads");
    assert_eq!(user.username, "");
}

#[tokio::test]
async fn other_tables_and_name_fields() {
    let db = database().await;
    let user = load::<Member>(&db, "bo").await.expect("bo loads");
    assert_eq!(user.username, "Bo");
    assert_eq!(user.record_id(), RecordId::new("member", "bo"));
}

#[tokio::test]
async fn the_session_store_round_trips() {
    let db = database().await;
    let pool = SurrealSessionPool::new(Arc::clone(&db));
    let later = chrono::Utc::now().timestamp() + 3600;
    let earlier = chrono::Utc::now().timestamp() - 3600;

    pool.store("live", "{\"a\":1}", later, "sessions")
        .await
        .expect("store");
    pool.store("stale", "{}", earlier, "sessions")
        .await
        .expect("store");

    assert_eq!(
        pool.load("live", "sessions").await.unwrap().as_deref(),
        Some("{\"a\":1}")
    );
    assert!(pool.exists("live", "sessions").await.unwrap());
    // Expired sessions read as absent before they are purged.
    assert_eq!(pool.load("stale", "sessions").await.unwrap(), None);
    assert!(!pool.exists("stale", "sessions").await.unwrap());
    assert_eq!(
        pool.get_ids("sessions").await.unwrap(),
        vec!["live".to_string()]
    );
    assert_eq!(pool.count("sessions").await.unwrap(), 2);

    // Storing again replaces rather than duplicating.
    pool.store("live", "{\"a\":2}", later, "sessions")
        .await
        .expect("store");
    assert_eq!(
        pool.load("live", "sessions").await.unwrap().as_deref(),
        Some("{\"a\":2}")
    );
    assert_eq!(pool.count("sessions").await.unwrap(), 2);

    assert_eq!(
        pool.delete_by_expiry("sessions").await.unwrap(),
        vec!["stale".to_string()]
    );
    pool.delete_one_by_id("live", "sessions").await.unwrap();
    assert_eq!(pool.count("sessions").await.unwrap(), 0);
}
