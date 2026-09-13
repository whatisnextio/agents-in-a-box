//! The `StartTask` service: `dispatched -> running`.
//!
//! After a runtime claims a task ([`crate::service::claim`]) and the runner
//! confirms the agent subprocess is live, [`StartTaskService::start`] flips the
//! row to `running` and stamps `started_at`. Unlike the three finalize-to-
//! terminal services, starting is *not* idempotent the same way: a second start
//! of an already-`running` task is a programming/race error surfaced as
//! [`FinalizeError::AlreadyStarted`] rather than a silent success, because two
//! live runs of one task is a real bug we want loud.

use ainb_hangar_core::clock::HangarClock;
use ainb_hangar_core::task::state::TaskState;
use sqlx::SqlitePool;

use super::finalize::{
    FinalizeError, FinalizeOutcome, finalize_idempotent, finalize_owned, record_workspace_id,
};

/// Stateless `dispatched -> running` service over `agent_task_queue`.
pub struct StartTaskService;

impl StartTaskService {
    /// Transition `task_id` from `dispatched` to `running`, stamping
    /// `started_at = clock.now_ms()`.
    ///
    /// Returns [`FinalizeOutcome::Transitioned`] on success.
    ///
    /// # Errors
    ///
    /// - [`FinalizeError::AlreadyStarted`] if the row is already `running`.
    /// - [`FinalizeError::TerminalMismatch`] if the row is already terminal.
    /// - [`FinalizeError::IllegalState`] if the row is `queued` or absent.
    /// - [`FinalizeError::Db`] on an underlying database error.
    #[tracing::instrument(
        name = "task.start",
        skip(pool, clock),
        fields(task_id = %task_id, workspace_id = tracing::field::Empty)
    )]
    pub async fn start(
        pool: &SqlitePool,
        task_id: &str,
        clock: &dyn HangarClock,
    ) -> Result<FinalizeOutcome, FinalizeError> {
        let now = clock.now_ms();
        record_workspace_id(pool, task_id).await;
        finalize_idempotent(
            pool,
            task_id,
            TaskState::Running,
            &[TaskState::Dispatched],
            "UPDATE agent_task_queue SET status = 'running', started_at = ?1 \
             WHERE id = ?2 AND status = 'dispatched'",
            move |q| q.bind(now).bind(task_id),
        )
        .await
    }

    /// Apply this worker transition only while its original claim epoch owns the row.
    ///
    /// # Errors
    /// Rejects stale ownership, invalid lifecycle states, and database failures.
    pub async fn start_owned(
        pool: &SqlitePool,
        task_id: &str,
        epoch: i64,
        clock: &dyn HangarClock,
    ) -> Result<FinalizeOutcome, FinalizeError> {
        let now = clock.now_ms();
        record_workspace_id(pool, task_id).await;
        finalize_owned(
            pool,
            task_id,
            epoch,
            TaskState::Running,
            &[TaskState::Dispatched],
            "UPDATE agent_task_queue SET status = 'running', started_at = ?1 \
             WHERE id = ?2 AND status = 'dispatched' AND execution_epoch = ?3 \
             AND (execution_root_id IS NULL OR EXISTS ( \
                 SELECT 1 FROM agent_task_queue root \
                 WHERE root.id = agent_task_queue.execution_root_id \
                 AND root.execution_owner_task_id = agent_task_queue.id \
                 AND root.execution_owner_epoch = agent_task_queue.execution_epoch \
                 AND root.execution_cancelled = 0 AND root.execution_published_task_id IS NULL \
             ))",
            move |q| q.bind(now).bind(task_id).bind(epoch),
        )
        .await
    }
}
