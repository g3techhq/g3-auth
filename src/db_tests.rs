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

fn account_session(id: Option<&str>) -> String {
    let data = id
        .map(|id| serde_json::json!({"user_auth_session_id": serde_json::to_string(id).unwrap()}))
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::json!({"data":data, "longterm":true}).to_string()
}

#[tokio::test]
async fn retirement_removes_tracked_and_legacy_sessions_without_removing_other_accounts() {
    let db = database().await;
    let legacy = SurrealSessionPool::new(Arc::clone(&db));
    let tracked = legacy.clone().track_accounts::<DefaultUser>();
    let expires = chrono::Utc::now().timestamp() + 3600;
    legacy
        .store(
            "legacy-a",
            &account_session(Some("ann")),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    legacy
        .store(
            "legacy-b",
            &account_session(Some("nameless")),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    legacy
        .store(
            "legacy-anonymous",
            &account_session(None),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    tracked
        .store(
            "tracked-a",
            &account_session(Some("ann")),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    tracked
        .store(
            "tracked-b",
            &account_session(Some("nameless")),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    let account = RecordId::new("user", "ann");
    tracked
        .retire_account_sessions("sessions", &account)
        .await
        .unwrap();
    for session in ["legacy-a", "tracked-a"] {
        assert!(tracked.load(session, "sessions").await.unwrap().is_none());
    }
    for session in ["legacy-b", "tracked-b", "legacy-anonymous"] {
        assert!(tracked.load(session, "sessions").await.unwrap().is_some());
    }
    // A delayed response, another device and a worker retry all keep the same
    // retired identity blocked, even while the app's account row still exists.
    tracked
        .store("late-a", &account_session(Some("ann")), expires, "sessions")
        .await
        .unwrap();
    assert!(tracked.load("late-a", "sessions").await.unwrap().is_none());
    tracked
        .retire_account_sessions("sessions", &account)
        .await
        .unwrap();
    assert!(
        tracked
            .retire_account_sessions("sessions", &RecordId::new("member", "ann"))
            .await
            .is_err()
    );
    assert!(
        legacy
            .retire_account_sessions("sessions", &account)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tracked_sessions_fail_closed_for_missing_accounts_and_unreadable_payloads() {
    let db = database().await;
    let legacy = SurrealSessionPool::new(Arc::clone(&db));
    let tracked = legacy.clone().track_accounts::<DefaultUser>();
    let expires = chrono::Utc::now().timestamp() + 3600;
    tracked
        .store(
            "missing",
            &account_session(Some("nobody")),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    assert!(tracked.load("missing", "sessions").await.unwrap().is_none());
    for invalid in [
        "encrypted-canary",
        "{}",
        r#"{"data":{"user_auth_session_id":"not-json-canary"}}"#,
        r#"{"data":{"user_auth_session_id":"123"}}"#,
    ] {
        let error = tracked
            .store("invalid", invalid, expires, "sessions")
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("canary"));
        assert!(tracked.load("invalid", "sessions").await.unwrap().is_none());
    }
    legacy
        .store("malformed-legacy", "encrypted-canary", expires, "sessions")
        .await
        .unwrap();
    assert!(
        tracked
            .retire_account_sessions("sessions", &RecordId::new("user", "ann"))
            .await
            .is_err()
    );
    // Failure to decode old data is pending cleanup, never a completion claim.
    assert!(
        legacy
            .load("malformed-legacy", "sessions")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn custom_auth_keys_are_tracked_and_legacy_indexing_preserves_payloads_and_expiry() {
    let db = database().await;
    let legacy = SurrealSessionPool::new(Arc::clone(&db));
    let tracked = legacy
        .clone()
        .track_accounts_with_key::<DefaultUser>("custom_auth");
    let expires = chrono::Utc::now().timestamp() + 3600;
    let body = serde_json::json!({"data":{"custom_auth":serde_json::to_string("ann").unwrap()},"longterm":true}).to_string();
    legacy
        .store("legacy", &body, expires, "sessions")
        .await
        .unwrap();
    tracked.index_account_sessions("sessions").await.unwrap();
    assert_eq!(
        tracked.load("legacy", "sessions").await.unwrap(),
        Some(body.clone())
    );
    let mut response = db
        .query("SELECT VALUE sessionexpires FROM sessions WHERE sessionid = 'legacy'")
        .await
        .unwrap();
    assert_eq!(
        response.take::<Option<String>>(0).unwrap(),
        Some(expires.to_string())
    );
    tracked
        .store("new", &body, expires, "sessions")
        .await
        .unwrap();
    tracked
        .retire_account_sessions("sessions", &RecordId::new("user", "ann"))
        .await
        .unwrap();
    assert_eq!(tracked.count("sessions").await.unwrap(), 0);
}

#[tokio::test]
async fn legacy_indexing_crosses_page_boundaries_and_requires_the_new_schema() {
    let db = database().await;
    let legacy = SurrealSessionPool::new(Arc::clone(&db));
    let tracked = legacy.clone().track_accounts::<DefaultUser>();
    let expires = chrono::Utc::now().timestamp() + 3600;
    for index in 0..130 {
        legacy
            .store(
                &format!("legacy-{index:03}"),
                &account_session(Some("ann")),
                expires,
                "sessions",
            )
            .await
            .unwrap();
    }
    tracked
        .retire_account_sessions("sessions", &RecordId::new("user", "ann"))
        .await
        .unwrap();
    assert_eq!(tracked.count("sessions").await.unwrap(), 0);
    db.query("REMOVE FIELD account_indexed ON sessions;")
        .await
        .unwrap()
        .check()
        .unwrap();
    legacy
        .store(
            "old-schema",
            &account_session(Some("nameless")),
            expires,
            "sessions",
        )
        .await
        .unwrap();
    assert!(tracked.index_account_sessions("sessions").await.is_err());
}

#[tokio::test]
async fn concurrent_session_writes_cannot_cross_the_retirement_fence() {
    let db = database().await;
    let pool = SurrealSessionPool::new(db).track_accounts::<DefaultUser>();
    let expires = chrono::Utc::now().timestamp() + 3600;
    let mut writes = Vec::new();
    for index in 0..24 {
        let writer = pool.clone();
        writes.push(tokio::spawn(async move {
            // A transaction conflict is allowed to fail closed. It must never
            // cause a later unguarded write after retirement succeeded.
            let _ = writer
                .store(
                    &format!("racing-{index}"),
                    &account_session(Some("ann")),
                    expires,
                    "sessions",
                )
                .await;
        }));
    }
    let account = RecordId::new("user", "ann");
    // The caller keeps a conflicted operation pending and retries it.
    let mut retired = false;
    for _ in 0..32 {
        if pool
            .retire_account_sessions("sessions", &account)
            .await
            .is_ok()
        {
            retired = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    for write in writes {
        write.await.unwrap();
    }
    pool.retire_account_sessions("sessions", &account)
        .await
        .unwrap();
    assert!(retired);
    assert_eq!(pool.count("sessions").await.unwrap(), 0);
    pool.store("late", &account_session(Some("ann")), expires, "sessions")
        .await
        .unwrap();
    assert_eq!(pool.count("sessions").await.unwrap(), 0);
}
