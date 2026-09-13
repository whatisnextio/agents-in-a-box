//! Automatic-continue admission against real temporary Store databases.
//! These tests qualify reserved units, not transport delivery or effect fencing.

use std::sync::Arc;
use std::time::Duration;

use ainb_hangar_store::Store;
use ainb_hangar_store::repo::atc_instance::{AtcInstanceRepo, RegisterAtc};
use tokio::sync::Barrier;
use tokio::task::JoinSet;

const INSTANCE: &str = "retry-admission-fixture";
const SESSION: &str = "synthetic-session";
const NOW: i64 = 1_700_000_000_000;
const CALLERS: usize = 16;

async fn register(store: &Store, cap: i64) {
    AtcInstanceRepo::register(
        store.pool(),
        &RegisterAtc {
            name: INSTANCE.into(),
            cwd: String::new(),
            tmux_session: None,
            heartbeat_cron: "0 */2 * * * *".into(),
            err_retry_cap: cap,
            idle_pause_min: 60,
            next_tick_at: None,
        },
        NOW,
    )
    .await
    .expect("register current authority");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reserve_continue_concurrent_callers_are_capped_and_unique() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    register(&store, 2).await;
    let barrier = Arc::new(Barrier::new(CALLERS + 1));
    let mut callers = JoinSet::new();
    for _ in 0..CALLERS {
        // Separate Store pools force contention between independent SQLite
        // connections; the parent pool cannot serialise these callers.
        let caller_store = Store::open_in(dir.path()).await.expect("independent caller store");
        let ready = Arc::clone(&barrier);
        callers.spawn(async move {
            ready.wait().await;
            let result =
                AtcInstanceRepo::reserve_continue(caller_store.pool(), INSTANCE, SESSION, NOW)
                    .await;
            caller_store.pool().close().await;
            result
        });
    }
    let mut admitted = tokio::time::timeout(Duration::from_secs(20), async {
        barrier.wait().await;
        let mut admitted = Vec::new();
        let mut denied = 0;
        while let Some(result) = callers.join_next().await {
            match result.expect("caller must finish").expect("no database error under contention") {
                Some(unit) => admitted.push(unit),
                None => denied += 1,
            }
        }
        assert_eq!(denied, CALLERS - 2);
        admitted
    })
    .await
    .expect("all barrier-released callers finish within the bound");
    admitted.sort_unstable();
    assert_eq!(
        admitted,
        vec![1, 2],
        "exact unique units from the authoritative statement"
    );
    let ledger = AtcInstanceRepo::retry_get(store.pool(), INSTANCE, SESSION)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.continue_count, 2);
    assert!(!ledger.escalated);
    store.pool().close().await;
}

#[tokio::test]
async fn reserve_continue_exhausted_and_escalated_are_denied() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    register(&store, 1).await;
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, SESSION, NOW)
            .await
            .unwrap(),
        Some(1)
    );
    let exhausted = AtcInstanceRepo::retry_get(store.pool(), INSTANCE, SESSION)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, SESSION, NOW + 1)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        AtcInstanceRepo::retry_get(store.pool(), INSTANCE, SESSION)
            .await
            .unwrap()
            .unwrap(),
        exhausted
    );

    AtcInstanceRepo::mark_escalated(store.pool(), INSTANCE, "escalated-session", NOW)
        .await
        .unwrap();
    let escalated = AtcInstanceRepo::retry_get(store.pool(), INSTANCE, "escalated-session")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(escalated.continue_count, 0);
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, "escalated-session", NOW + 1)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        AtcInstanceRepo::retry_get(store.pool(), INSTANCE, "escalated-session")
            .await
            .unwrap()
            .unwrap(),
        escalated
    );
    store.pool().close().await;
}

#[tokio::test]
async fn reserve_continue_uses_current_registered_cap() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    register(&store, 5).await;
    let stale = AtcInstanceRepo::get(store.pool(), INSTANCE).await.unwrap().unwrap();
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, SESSION, NOW)
            .await
            .unwrap(),
        Some(1)
    );
    register(&store, 1).await;
    assert_eq!(
        stale.err_retry_cap, 5,
        "caller still holds the old snapshot"
    );
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), &stale.name, SESSION, NOW + 1)
            .await
            .unwrap(),
        None
    );
    register(&store, 2).await;
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), &stale.name, SESSION, NOW + 2)
            .await
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), &stale.name, SESSION, NOW + 3)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        AtcInstanceRepo::retry_get(store.pool(), INSTANCE, SESSION)
            .await
            .unwrap()
            .unwrap()
            .continue_count,
        2
    );
    store.pool().close().await;
}

#[tokio::test]
async fn reserve_continue_missing_authority_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, SESSION, NOW)
            .await
            .unwrap(),
        None
    );
    assert!(
        AtcInstanceRepo::retry_get(store.pool(), INSTANCE, SESSION)
            .await
            .unwrap()
            .is_none()
    );
    store.pool().close().await;
}

#[tokio::test]
async fn reserve_continue_budget_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    register(&store, 2).await;
    assert_eq!(
        AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, SESSION, NOW)
            .await
            .unwrap(),
        Some(1)
    );
    store.pool().close().await;
    drop(store);
    let reopened = Store::open_in(dir.path()).await.unwrap();
    assert_eq!(
        AtcInstanceRepo::retry_get(reopened.pool(), INSTANCE, SESSION)
            .await
            .unwrap()
            .unwrap()
            .continue_count,
        1
    );
    assert_eq!(
        AtcInstanceRepo::reserve_continue(reopened.pool(), INSTANCE, SESSION, NOW + 1)
            .await
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        AtcInstanceRepo::reserve_continue(reopened.pool(), INSTANCE, SESSION, NOW + 2)
            .await
            .unwrap(),
        None
    );
    reopened.pool().close().await;
}

#[tokio::test]
async fn reserve_continue_closed_store_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    register(&store, 2).await;
    store.pool().close().await;
    let result = AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, SESSION, NOW).await;
    assert!(
        matches!(result, Err(sqlx::Error::PoolClosed)),
        "closed authority must error, not admit or appear exhausted: {result:?}"
    );
}

#[tokio::test]
async fn reserve_continue_disabled_instance_preserves_minimum_cap_policy() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    for (cap, session) in [(0, "zero-cap"), (-4, "negative-cap")] {
        register(&store, cap).await;
        AtcInstanceRepo::set_enabled(store.pool(), INSTANCE, false, None).await.unwrap();
        assert!(!AtcInstanceRepo::get(store.pool(), INSTANCE).await.unwrap().unwrap().enabled);
        assert_eq!(
            AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, session, NOW)
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            AtcInstanceRepo::reserve_continue(store.pool(), INSTANCE, session, NOW + 1)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            AtcInstanceRepo::retry_get(store.pool(), INSTANCE, session)
                .await
                .unwrap()
                .unwrap()
                .continue_count,
            1
        );
    }
    store.pool().close().await;
}
