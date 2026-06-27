-- +goose Up
-- Presence events: the tamper-evident record of who joined/left a live session
-- and when — the Decree 147 "presence" signal. Operational membership (the
-- currently-present set) lives in session_participants; THIS is the append-only,
-- immutable evidentiary trail of connections and departures.
--
-- Per ADR-010 (see DECISIONS.md): the join/leave hot path writes here cheaply — a
-- plain INSERT, no advisory lock and no per-event signature. Cryptographic
-- tamper-evidence is added out-of-band (stage 2) by a periodic Merkle checkpoint
-- that folds a Vault-signed root over these rows into audit_log. Immutability is
-- enforced HERE and now by a trigger (mirroring audit_log / consent_records), so
-- rows are unalterable from the instant they land — which covers the window
-- before a checkpoint anchors them.
CREATE TABLE presence_events (
    seq         bigserial PRIMARY KEY,            -- monotonic order; the unit a checkpoint covers
    id          text NOT NULL UNIQUE,             -- opaque ULID-shaped id
    session_id  text NOT NULL REFERENCES sessions(id),
    user_id     text NOT NULL REFERENCES users(id),
    action      text NOT NULL CHECK (action IN ('join','leave')),
    role        text NOT NULL,                    -- role at the time: host | participant
    occurred_at timestamptz NOT NULL DEFAULT now()
);

-- Forensic lookup: "who was in this session, in order".
CREATE INDEX presence_events_session_idx ON presence_events (session_id, seq);
-- Per-user view: "which sessions was this user present in".
CREATE INDEX presence_events_user_idx ON presence_events (user_id, seq);

-- +goose StatementBegin
-- Immutability: presence_events is insert-only. Any UPDATE or DELETE raises, so
-- presence history cannot be rewritten in place (row replacement is separately
-- defeated by the checkpoint Merkle root once stage 2 lands).
CREATE OR REPLACE FUNCTION presence_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'presence_events is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER presence_events_no_update BEFORE UPDATE ON presence_events
    FOR EACH ROW EXECUTE FUNCTION presence_events_immutable();
CREATE TRIGGER presence_events_no_delete BEFORE DELETE ON presence_events
    FOR EACH ROW EXECUTE FUNCTION presence_events_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS presence_events_no_delete ON presence_events;
DROP TRIGGER IF EXISTS presence_events_no_update ON presence_events;
DROP FUNCTION IF EXISTS presence_events_immutable();
DROP TABLE IF EXISTS presence_events;
