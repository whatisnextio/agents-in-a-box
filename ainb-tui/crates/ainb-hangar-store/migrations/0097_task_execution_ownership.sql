-- A claim owns one epoch. Optional execution allowance belongs to the logical
-- root, so restart redelivery and retry children spend the same durable units.
ALTER TABLE agent_task_queue ADD COLUMN execution_epoch INTEGER NOT NULL DEFAULT 0 CHECK (execution_epoch >= 0);
ALTER TABLE agent_task_queue ADD COLUMN execution_limit INTEGER CHECK (execution_limit > 0);
ALTER TABLE agent_task_queue ADD COLUMN execution_units INTEGER NOT NULL DEFAULT 0 CHECK (execution_units >= 0);
ALTER TABLE agent_task_queue ADD COLUMN execution_root_id TEXT REFERENCES agent_task_queue(id);
ALTER TABLE agent_task_queue ADD COLUMN execution_owner_task_id TEXT REFERENCES agent_task_queue(id);
ALTER TABLE agent_task_queue ADD COLUMN execution_owner_epoch INTEGER;
ALTER TABLE agent_task_queue ADD COLUMN execution_published_task_id TEXT REFERENCES agent_task_queue(id);
ALTER TABLE agent_task_queue ADD COLUMN execution_cancelled INTEGER NOT NULL DEFAULT 0 CHECK (execution_cancelled IN (0, 1));

CREATE TRIGGER task_execution_inherit AFTER INSERT ON agent_task_queue
WHEN NEW.parent_task_id IS NOT NULL
BEGIN
    UPDATE agent_task_queue SET
        execution_root_id = (SELECT execution_root_id FROM agent_task_queue WHERE id = NEW.parent_task_id),
        execution_limit = (SELECT root.execution_limit FROM agent_task_queue parent
            JOIN agent_task_queue root ON root.id = parent.execution_root_id
            WHERE parent.id = NEW.parent_task_id)
    WHERE id = NEW.id;
END;

-- The guard and charge execute inside the claim statement, including rollback.
CREATE TRIGGER task_execution_admit BEFORE UPDATE OF status ON agent_task_queue
WHEN NEW.status = 'dispatched' AND OLD.status = 'queued'
     AND OLD.execution_root_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM agent_task_queue root WHERE root.id = OLD.execution_root_id
        AND root.execution_limit IS NOT NULL AND root.execution_units < root.execution_limit
        AND root.execution_owner_task_id IS NULL
        AND root.execution_published_task_id IS NULL AND root.execution_cancelled = 0
    ) THEN RAISE(ABORT, 'task execution admission denied') END;
END;

CREATE TRIGGER task_execution_charge AFTER UPDATE OF status ON agent_task_queue
WHEN NEW.status = 'dispatched' AND OLD.status = 'queued'
     AND OLD.execution_root_id IS NOT NULL
BEGIN
    UPDATE agent_task_queue SET execution_units = execution_units + 1,
        execution_owner_task_id = NEW.id, execution_owner_epoch = NEW.execution_epoch
    WHERE id = OLD.execution_root_id;
END;

-- Failed/reclaimed workers relinquish the logical owner, never its spent units.
CREATE TRIGGER task_execution_release AFTER UPDATE OF status ON agent_task_queue
WHEN OLD.status IN ('dispatched', 'running') AND NEW.status IN ('queued', 'failed')
     AND OLD.execution_root_id IS NOT NULL
BEGIN
    UPDATE agent_task_queue SET execution_owner_task_id = NULL, execution_owner_epoch = NULL
    WHERE id = OLD.execution_root_id AND execution_owner_task_id = OLD.id
        AND execution_owner_epoch = OLD.execution_epoch;
END;

-- Cancelling any member closes the whole logical lineage, including retries
-- created later from an older failed ancestor.
CREATE TRIGGER task_execution_cancel_lineage AFTER UPDATE OF status ON agent_task_queue
WHEN NEW.status = 'cancelled' AND OLD.status <> 'cancelled'
     AND OLD.execution_root_id IS NOT NULL
BEGIN
    UPDATE agent_task_queue SET execution_cancelled = 1,
        execution_owner_task_id = NULL, execution_owner_epoch = NULL
    WHERE id = OLD.execution_root_id AND execution_published_task_id IS NULL;
END;

CREATE TRIGGER task_execution_publish_guard BEFORE UPDATE OF status ON agent_task_queue
WHEN NEW.status = 'done' AND OLD.status <> 'done' AND OLD.execution_root_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM agent_task_queue root WHERE root.id = OLD.execution_root_id
        AND root.execution_owner_task_id = OLD.id AND root.execution_owner_epoch = OLD.execution_epoch
        AND root.execution_cancelled = 0 AND root.execution_published_task_id IS NULL
    ) THEN RAISE(ABORT, 'task execution publication denied') END;
END;

CREATE TRIGGER task_execution_publish AFTER UPDATE OF status ON agent_task_queue
WHEN NEW.status = 'done' AND OLD.status <> 'done' AND OLD.execution_root_id IS NOT NULL
BEGIN
    UPDATE agent_task_queue SET execution_published_task_id = NEW.id
    WHERE id = OLD.execution_root_id;
END;

-- Existing controller/sweeper transitions also revoke stale worker authority.
CREATE TRIGGER task_execution_revoke AFTER UPDATE OF status ON agent_task_queue
WHEN (NEW.status = 'queued' AND OLD.status IN ('dispatched', 'running'))
     OR (NEW.status = 'cancelled' AND OLD.status <> 'cancelled')
BEGIN
    UPDATE agent_task_queue SET execution_epoch = execution_epoch + 1 WHERE id = NEW.id;
END;
