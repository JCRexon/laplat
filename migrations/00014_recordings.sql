-- +goose Up
-- Recordings (stream C; consumes the consent ledger's RecordingAllowed gate).
-- A recording is the operational state of one LiveKit egress for a session:
-- unlike consent_records (an append-only legal ledger), this is mutable state
-- that transitions starting → active → completed/failed/aborted as egress
-- progresses. The egress is only ever started when every present participant
-- has consented (D-2), and a withdrawal stops it.
CREATE TABLE recordings (
    id         text PRIMARY KEY,                       -- our id (ULID-shaped)
    session_id text NOT NULL REFERENCES sessions(id),
    egress_id  text,                                   -- LiveKit egress id (null until accepted)
    status     text NOT NULL CHECK (status IN
                   ('starting','active','stopping','completed','failed','aborted')),
    output_uri text,                                   -- where the file landed (null until known)
    error      text,                                   -- failure detail, if any
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at   timestamptz                             -- set on a terminal status
);

-- A session's recordings, newest first (the control/listing path).
CREATE INDEX recordings_session_idx ON recordings (session_id, started_at DESC);

-- At most one in-flight recording per session: starting a second while one is
-- live is a logic error, and the gate/stop reconciliation assumes a single
-- active egress per session.
CREATE UNIQUE INDEX recordings_one_active_idx ON recordings (session_id)
    WHERE status IN ('starting', 'active', 'stopping');

-- +goose Down
DROP INDEX IF EXISTS recordings_one_active_idx;
DROP INDEX IF EXISTS recordings_session_idx;
DROP TABLE IF EXISTS recordings;
