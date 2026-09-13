//! Real Store ownership and logical execution allowance tests. No provider effects.
use ainb_hangar_core::clock::FixedClock;
use ainb_hangar_store::service::{
    cancel::CancelTaskService,
    claim::{ClaimTaskService, ClaimedTask},
    complete::{CompleteParams, CompleteTaskService},
    fail::{FailTaskService, FailureReason},
    finalize::{FinalizeError, FinalizeOutcome},
    retry::{RetryDecision, RetryService},
    start::StartTaskService,
};
use ainb_hangar_store::{
    Store,
    repo::task::{NewTask, Task, TaskRepo},
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Barrier, task::JoinSet};
const CLOCK: FixedClock = FixedClock(1_700_000_000_000);

async fn seed_graph(store: &Store) {
    let pool = store.pool();
    sqlx::query("INSERT OR IGNORE INTO workspace (id, slug, name, created_at) VALUES (?, ?, ?, ?)")
        .bind("ws-1")
        .bind("alpha")
        .bind("Alpha")
        .bind(0_i64)
        .execute(pool)
        .await
        .expect("insert workspace");
    sqlx::query("INSERT OR IGNORE INTO user (id, email, created_at) VALUES (?, ?, ?)")
        .bind("user-1")
        .bind("a@example.com")
        .bind(0_i64)
        .execute(pool)
        .await
        .expect("insert user");
    sqlx::query(
        "INSERT INTO agent_runtime (id, workspace_id, daemon_id, provider, runtime_mode) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind("rt-1")
    .bind("ws-1")
    .bind("daemon-rt-1")
    .bind("claude")
    .bind("local")
    .execute(pool)
    .await
    .expect("insert runtime");
    sqlx::query(
        "INSERT INTO agent \
         (id, workspace_id, name, runtime_id, visibility, owner_id, max_concurrent_tasks) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("agent-1")
    .bind("ws-1")
    .bind("Agent")
    .bind("rt-1")
    .bind("workspace")
    .bind("user-1")
    .bind(5_i64)
    .execute(pool)
    .await
    .expect("insert agent");
}

async fn fixture(cap: i64) -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in(dir.path()).await.unwrap();
    seed_graph(&store).await;
    sqlx::query("UPDATE agent SET max_concurrent_tasks=32 WHERE id='agent-1'")
        .execute(store.pool())
        .await
        .unwrap();
    TaskRepo::insert(
        store.pool(),
        &NewTask {
            id: "root".into(),
            workspace_id: "ws-1".into(),
            runtime_id: "rt-1".into(),
            agent_id: "agent-1".into(),
            issue_id: None,
            work_dir: None,
            priority: 0,
            created_at: 1,
            autopilot_run_id: None,
            generation: 0,
        },
    )
    .await
    .unwrap();
    assert!(TaskRepo::configure_execution_limit(store.pool(), "root", cap).await.unwrap());
    (dir, store)
}
async fn task(store: &Store, id: &str) -> Task {
    TaskRepo::get_by_id(store.pool(), id).await.unwrap().unwrap()
}
async fn claim(store: &Store) -> ClaimedTask {
    ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
        .await
        .unwrap()
        .unwrap()
}
async fn units(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT execution_units FROM agent_task_queue WHERE id='root'")
        .fetch_one(store.pool())
        .await
        .unwrap()
}
async fn reclaim(store: &Store) {
    // Same status transition used by daemon restart/stale-dispatch sweepers.
    sqlx::query("UPDATE agent_task_queue SET status='queued', started_at=NULL, dispatched_at=NULL WHERE id='root' AND status IN ('dispatched','running')")
        .execute(store.pool()).await.unwrap();
}
fn result(text: &str) -> CompleteParams {
    CompleteParams {
        result: serde_json::json!({"content":text}),
        session_id: None,
        work_dir: None,
    }
}
fn stale(outcome: Result<FinalizeOutcome, FinalizeError>, expected: i64, actual: i64) {
    assert!(
        matches!(outcome,Err(FinalizeError::StaleExecution{expected:e,actual:a}) if e==expected && a==actual)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retry_children_share_exact_root_allowance() {
    let (dir, store) = fixture(2).await;
    FailTaskService::fail(store.pool(), "root", FailureReason::RuntimeOffline, &CLOCK)
        .await
        .unwrap();
    let parent = task(&store, "root").await;
    for n in 0..16 {
        assert!(matches!(
            RetryService::force_requeue(store.pool(), &parent, &format!("child-{n:02}"), &CLOCK)
                .await
                .unwrap(),
            RetryDecision::Spawned { .. }
        ));
    }
    let barrier = Arc::new(Barrier::new(17));
    let mut callers = JoinSet::new();
    for _ in 0..16 {
        let independent = Store::open_in(dir.path()).await.unwrap();
        let ready = Arc::clone(&barrier);
        callers.spawn(async move {
            ready.wait().await;
            let got = ClaimTaskService::claim_for_runtime(independent.pool(), "rt-1", &CLOCK).await;
            independent.pool().close().await;
            got
        });
    }
    let claimed = tokio::time::timeout(Duration::from_secs(20), async {
        barrier.wait().await;
        let mut admitted = Vec::new();
        let mut denied = 0;
        while let Some(got) = callers.join_next().await {
            match got.unwrap().expect("contention must not cause DB error") {
                Some(c) => admitted.push(c),
                None => denied += 1,
            }
        }
        assert_eq!(denied, 15);
        admitted
    })
    .await
    .expect("bounded concurrent independent pools");
    assert_eq!(claimed.len(), 1);
    let first = &claimed[0];
    assert_eq!(first.execution_epoch, 1);
    assert_eq!(first.execution_limit, Some(2));
    assert_eq!(units(&store).await, 1);
    let active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_task_queue WHERE status='dispatched'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(active, 1);
    FailTaskService::fail_setup_owned(
        store.pool(),
        &first.id,
        first.execution_epoch,
        FailureReason::SpawnError,
        "release first logical owner",
        &CLOCK,
    )
    .await
    .unwrap();
    let second = claim(&store).await;
    assert_ne!(first.id, second.id);
    assert_eq!(units(&store).await, 2);
    FailTaskService::fail_setup_owned(
        store.pool(),
        &second.id,
        second.execution_epoch,
        FailureReason::SpawnError,
        "release second logical owner",
        &CLOCK,
    )
    .await
    .unwrap();
    assert!(
        ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(units(&store).await, 2);
    store.pool().close().await;
}

#[tokio::test]
async fn reclaim_and_reopen_preserve_spent_execution_allowance() {
    let (dir, store) = fixture(2).await;
    let first = claim(&store).await;
    assert_eq!(first.execution_epoch, 1);
    reclaim(&store).await;
    let second = claim(&store).await;
    assert_eq!(second.execution_epoch, 3);
    reclaim(&store).await;
    assert_eq!(units(&store).await, 2);
    assert!(!TaskRepo::configure_execution_limit(store.pool(), "root", 100).await.unwrap());
    store.pool().close().await;
    let reopened = Store::open_in(dir.path()).await.unwrap();
    assert_eq!(units(&reopened).await, 2);
    assert_eq!(task(&reopened, "root").await.execution_epoch, 4);
    assert!(
        ClaimTaskService::claim_for_runtime(reopened.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(task(&reopened, "root").await.status, "queued");
    reopened.pool().close().await;
}

#[tokio::test]
async fn stale_worker_writes_cannot_replace_successor_or_replay_its_done() {
    let (_dir, store) = fixture(2).await;
    let first = claim(&store).await;
    StartTaskService::start_owned(store.pool(), "root", first.execution_epoch, &CLOCK)
        .await
        .unwrap();
    reclaim(&store).await;
    let next = claim(&store).await;
    stale(
        StartTaskService::start_owned(store.pool(), "root", first.execution_epoch, &CLOCK).await,
        first.execution_epoch,
        next.execution_epoch,
    );
    stale(
        FailTaskService::fail_setup_owned(
            store.pool(),
            "root",
            first.execution_epoch,
            FailureReason::SpawnError,
            "stale",
            &CLOCK,
        )
        .await,
        first.execution_epoch,
        next.execution_epoch,
    );
    StartTaskService::start_owned(store.pool(), "root", next.execution_epoch, &CLOCK)
        .await
        .unwrap();
    stale(
        CompleteTaskService::complete_owned(
            store.pool(),
            "root",
            first.execution_epoch,
            result("stale"),
            &CLOCK,
        )
        .await,
        first.execution_epoch,
        next.execution_epoch,
    );
    stale(
        FailTaskService::fail_owned(
            store.pool(),
            "root",
            first.execution_epoch,
            FailureReason::AgentError,
            &CLOCK,
        )
        .await,
        first.execution_epoch,
        next.execution_epoch,
    );
    stale(
        FailTaskService::fail_with_detail_owned(
            store.pool(),
            "root",
            first.execution_epoch,
            FailureReason::AgentError,
            "stale",
            &CLOCK,
        )
        .await,
        first.execution_epoch,
        next.execution_epoch,
    );
    assert_eq!(
        CompleteTaskService::complete_owned(
            store.pool(),
            "root",
            next.execution_epoch,
            result("authoritative"),
            &CLOCK
        )
        .await
        .unwrap(),
        FinalizeOutcome::Transitioned
    );
    let committed = task(&store, "root").await;
    stale(
        CompleteTaskService::complete_owned(
            store.pool(),
            "root",
            first.execution_epoch,
            result("stale terminal replay"),
            &CLOCK,
        )
        .await,
        first.execution_epoch,
        next.execution_epoch,
    );
    assert_eq!(
        CompleteTaskService::complete_owned(
            store.pool(),
            "root",
            next.execution_epoch,
            result("same epoch replay"),
            &CLOCK
        )
        .await
        .unwrap(),
        FinalizeOutcome::AlreadyTerminal
    );
    assert_eq!(task(&store, "root").await, committed);
    assert_eq!(
        committed.result,
        Some(serde_json::json!({"content":"authoritative"}).to_string())
    );
    store.pool().close().await;
}

#[tokio::test]
async fn cancellation_revokes_claim_before_worker_finalization() {
    let (_dir, store) = fixture(2).await;
    let owned = claim(&store).await;
    StartTaskService::start_owned(store.pool(), "root", owned.execution_epoch, &CLOCK)
        .await
        .unwrap();
    CancelTaskService::cancel(store.pool(), "root", &CLOCK).await.unwrap();
    let cancelled = task(&store, "root").await;
    assert_eq!(cancelled.status, "cancelled");
    assert_eq!(cancelled.execution_epoch, owned.execution_epoch + 1);
    stale(
        CompleteTaskService::complete_owned(
            store.pool(),
            "root",
            owned.execution_epoch,
            result("late"),
            &CLOCK,
        )
        .await,
        owned.execution_epoch,
        cancelled.execution_epoch,
    );
    stale(
        FailTaskService::fail_owned(
            store.pool(),
            "root",
            owned.execution_epoch,
            FailureReason::AgentError,
            &CLOCK,
        )
        .await,
        owned.execution_epoch,
        cancelled.execution_epoch,
    );
    assert_eq!(task(&store, "root").await, cancelled);
    assert_eq!(units(&store).await, 1);
    store.pool().close().await;
}

#[tokio::test]
async fn automatic_and_manual_retry_cannot_replenish_exhausted_root() {
    let (_dir, store) = fixture(1).await;
    let owned = claim(&store).await;
    StartTaskService::start_owned(store.pool(), "root", owned.execution_epoch, &CLOCK)
        .await
        .unwrap();
    FailTaskService::fail_owned(
        store.pool(),
        "root",
        owned.execution_epoch,
        FailureReason::RuntimeOffline,
        &CLOCK,
    )
    .await
    .unwrap();
    // Permit automatic retry by the independent legacy attempt policy.
    sqlx::query("UPDATE agent_task_queue SET max_attempts=3 WHERE id='root'")
        .execute(store.pool())
        .await
        .unwrap();
    let parent = task(&store, "root").await;
    assert!(matches!(
        RetryService::maybe_retry_failed(store.pool(), &parent, "auto-child", &CLOCK)
            .await
            .unwrap(),
        RetryDecision::Spawned { .. }
    ));
    assert!(matches!(
        RetryService::force_requeue(store.pool(), &parent, "manual-child", &CLOCK)
            .await
            .unwrap(),
        RetryDecision::Spawned { .. }
    ));
    for id in ["auto-child", "manual-child"] {
        assert_eq!(task(&store, id).await.execution_limit, Some(1));
        assert!(!TaskRepo::configure_execution_limit(store.pool(), id, 100).await.unwrap());
    }
    assert!(
        ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(units(&store).await, 1);
    store.pool().close().await;
}

#[tokio::test]
async fn configuration_rejects_invalid_or_spent_limits_and_closed_store_errors() {
    let (_dir, store) = fixture(2).await;
    assert!(!TaskRepo::configure_execution_limit(store.pool(), "root", 0).await.unwrap());
    assert!(!TaskRepo::configure_execution_limit(store.pool(), "missing", 2).await.unwrap());
    assert!(TaskRepo::configure_execution_limit(store.pool(), "root", 1).await.unwrap());
    assert_eq!(claim(&store).await.execution_limit, Some(1));
    assert!(!TaskRepo::configure_execution_limit(store.pool(), "root", 10).await.unwrap());
    assert_eq!(units(&store).await, 1);
    store.pool().close().await;
    assert!(ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK).await.is_err());
    assert!(TaskRepo::configure_execution_limit(store.pool(), "root", 10).await.is_err());
}

#[tokio::test]
async fn retry_claim_reads_current_root_allowance_and_guard_rolls_back() {
    let (_dir, store) = fixture(2).await;
    FailTaskService::fail(store.pool(), "root", FailureReason::RuntimeOffline, &CLOCK)
        .await
        .unwrap();
    let parent = task(&store, "root").await;
    for id in ["child-a", "child-b"] {
        assert!(matches!(
            RetryService::force_requeue(store.pool(), &parent, id, &CLOCK).await.unwrap(),
            RetryDecision::Spawned { .. }
        ));
    }
    // Simulate a durable owner-policy tightening; children retain their old
    // copied column, so the root must remain the actual claim authority.
    sqlx::query("UPDATE agent_task_queue SET execution_limit=1 WHERE id='root'")
        .execute(store.pool())
        .await
        .unwrap();
    let copied: i64 =
        sqlx::query_scalar("SELECT execution_limit FROM agent_task_queue WHERE id='child-b'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(copied, 2);
    let admitted = claim(&store).await;
    assert_eq!(admitted.id, "child-a");
    assert_eq!(admitted.execution_limit, Some(1));
    assert_eq!(task(&store, "child-b").await.execution_limit, Some(1));
    let before = task(&store, "child-b").await;
    assert!(
        ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    // Hard trigger guards even a legacy direct dispatch UPDATE, atomically.
    assert!(sqlx::query("UPDATE agent_task_queue SET status='dispatched',execution_epoch=execution_epoch+1 WHERE id='child-b'").execute(store.pool()).await.is_err());
    assert_eq!(task(&store, "child-b").await, before);
    assert_eq!(units(&store).await, 1);
    store.pool().close().await;
}

#[tokio::test]
async fn logical_publication_winner_rejects_other_children_and_preserves_exact_replay() {
    let (dir, store) = fixture(3).await;
    FailTaskService::fail(store.pool(), "root", FailureReason::RuntimeOffline, &CLOCK)
        .await
        .unwrap();
    let parent = task(&store, "root").await;
    for id in ["child-a", "child-b", "child-c"] {
        assert!(matches!(
            RetryService::force_requeue(store.pool(), &parent, id, &CLOCK).await.unwrap(),
            RetryDecision::Spawned { .. }
        ));
    }
    let first = claim(&store).await;
    StartTaskService::start_owned(store.pool(), &first.id, first.execution_epoch, &CLOCK)
        .await
        .unwrap();
    assert!(
        ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    FailTaskService::fail_owned(
        store.pool(),
        &first.id,
        first.execution_epoch,
        FailureReason::RuntimeOffline,
        &CLOCK,
    )
    .await
    .unwrap();
    let winner = claim(&store).await;
    assert_ne!(winner.id, first.id);
    // Both children carry epoch1: identity as well as epoch must be checked.
    assert_eq!(winner.execution_epoch, first.execution_epoch);
    StartTaskService::start_owned(store.pool(), &winner.id, winner.execution_epoch, &CLOCK)
        .await
        .unwrap();
    assert!(matches!(
        CompleteTaskService::complete_owned(
            store.pool(),
            &first.id,
            first.execution_epoch,
            result("stale sibling"),
            &CLOCK
        )
        .await,
        Err(FinalizeError::OwnershipRevoked { .. })
    ));
    CompleteTaskService::complete_owned(
        store.pool(),
        &winner.id,
        winner.execution_epoch,
        result("one logical report"),
        &CLOCK,
    )
    .await
    .unwrap();
    let committed = task(&store, &winner.id).await;
    let published: String = sqlx::query_scalar(
        "SELECT execution_published_task_id FROM agent_task_queue WHERE id='root'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(published, winner.id);
    // Cancelling an unused sibling after publication cannot revoke the winner.
    let unused = ["child-a", "child-b", "child-c"]
        .into_iter()
        .find(|id| *id != first.id && *id != winner.id)
        .unwrap();
    assert_eq!(
        CancelTaskService::cancel(store.pool(), unused, &CLOCK).await.unwrap(),
        FinalizeOutcome::Transitioned
    );
    let cancelled: i64 =
        sqlx::query_scalar("SELECT execution_cancelled FROM agent_task_queue WHERE id='root'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(cancelled, 0);
    assert!(matches!(
        CompleteTaskService::complete_owned(
            store.pool(),
            &first.id,
            first.execution_epoch,
            result("late sibling"),
            &CLOCK
        )
        .await,
        Err(FinalizeError::OwnershipRevoked { .. })
    ));
    assert_eq!(
        CompleteTaskService::complete_owned(
            store.pool(),
            &winner.id,
            winner.execution_epoch,
            result("replay differs"),
            &CLOCK
        )
        .await
        .unwrap(),
        FinalizeOutcome::AlreadyTerminal
    );
    assert_eq!(task(&store, &winner.id).await, committed);
    assert!(matches!(
        RetryService::force_requeue(store.pool(), &parent, "late-child", &CLOCK)
            .await
            .unwrap(),
        RetryDecision::Spawned { .. }
    ));
    assert!(
        ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(units(&store).await, 2); // cap3 still has one unit; publication denies it.
    let published_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_task_queue WHERE status='done'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(published_count, 1);
    store.pool().close().await;
    let reopened = Store::open_in(dir.path()).await.unwrap();
    assert!(
        ClaimTaskService::claim_for_runtime(reopened.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        CompleteTaskService::complete_owned(
            reopened.pool(),
            &winner.id,
            winner.execution_epoch,
            result("restart replay differs"),
            &CLOCK
        )
        .await
        .unwrap(),
        FinalizeOutcome::AlreadyTerminal
    );
    assert_eq!(task(&reopened, &winner.id).await, committed);
    reopened.pool().close().await;
}

#[tokio::test]
async fn cancelled_child_revokes_logical_root_and_blocks_failed_ancestor_retries() {
    let (dir, store) = fixture(3).await;
    FailTaskService::fail(store.pool(), "root", FailureReason::RuntimeOffline, &CLOCK)
        .await
        .unwrap();
    let parent = task(&store, "root").await;
    assert!(matches!(
        RetryService::force_requeue(store.pool(), &parent, "child", &CLOCK)
            .await
            .unwrap(),
        RetryDecision::Spawned { .. }
    ));
    let child = claim(&store).await;
    StartTaskService::start_owned(store.pool(), &child.id, child.execution_epoch, &CLOCK)
        .await
        .unwrap();
    CancelTaskService::cancel(store.pool(), &child.id, &CLOCK).await.unwrap();
    let cancelled: i64 =
        sqlx::query_scalar("SELECT execution_cancelled FROM agent_task_queue WHERE id='root'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(cancelled, 1);
    assert!(matches!(
        RetryService::force_requeue(store.pool(), &parent, "manual-after-cancel", &CLOCK)
            .await
            .unwrap(),
        RetryDecision::Spawned { .. }
    ));
    assert!(
        ClaimTaskService::claim_for_runtime(store.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    stale(
        CompleteTaskService::complete_owned(
            store.pool(),
            &child.id,
            child.execution_epoch,
            result("after cancellation"),
            &CLOCK,
        )
        .await,
        child.execution_epoch,
        child.execution_epoch + 1,
    );
    assert_eq!(units(&store).await, 1);
    assert_eq!(task(&store, "root").await.status, "failed");
    assert_eq!(task(&store, "manual-after-cancel").await.status, "queued");
    store.pool().close().await;
    let reopened = Store::open_in(dir.path()).await.unwrap();
    assert!(
        ClaimTaskService::claim_for_runtime(reopened.pool(), "rt-1", &CLOCK)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(units(&reopened).await, 1);
    reopened.pool().close().await;
}
