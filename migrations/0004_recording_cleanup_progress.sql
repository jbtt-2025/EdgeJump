-- Object deletion is idempotent; a cursor survives cron restarts and request budgets.
CREATE TABLE recording_cleanup_jobs (
  session_id TEXT PRIMARY KEY REFERENCES ssh_sessions(id) ON DELETE CASCADE,
  chunk_count INTEGER,
  next_chunk INTEGER NOT NULL DEFAULT 1,
  lease_id TEXT,
  lease_until INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_recording_retention ON ssh_sessions(recording_status, COALESCE(ended_at, started_at))
  WHERE recording_path IS NOT NULL AND recording_path != '';
