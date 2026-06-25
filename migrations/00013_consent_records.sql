-- +goose Up
-- The consent ledger (contracts §3; A-2 / D-2 / X-4): an append-only, hash-
-- chained, server-signed record of recording-consent grants and withdrawals.
-- Decree 147 / PDPL require demonstrable consent before a session is recorded,
-- and a withdrawal must be able to stop it — so storage is insert-only and
-- tamper-evident (same discipline as audit_log). Effective consent is the
-- LATEST record per (subject_id, session_id, purpose); a withdrawal is a new
-- granted=false row, never an UPDATE/DELETE.
CREATE TABLE consent_records (
    seq            bigserial PRIMARY KEY,             -- chain order
    id             text NOT NULL,                     -- ULID-shaped record id
    session_id     text NOT NULL,                     -- the session consent is about (no FK: a consent outlives a session row)
    subject_id     text NOT NULL REFERENCES users(id),
    purpose        text NOT NULL,                     -- e.g. 'session_recording'
    granted        boolean NOT NULL,                  -- false = withdrawal
    granted_at     timestamptz NOT NULL DEFAULT now(),
    prev_hash      bytea NOT NULL,                    -- record_hash of seq-1 (32 zero bytes at genesis)
    record_hash    bytea NOT NULL,                    -- sha256 over the canonical SignedPayload
    signing_key_id text NOT NULL,                     -- key id, for rotation-safe verification
    signature      bytea NOT NULL                     -- ed25519 over the SignedPayload
);

-- Effective-consent lookup (latest per subject+session+purpose) and per-session
-- scans (the recording gate).
CREATE INDEX consent_records_effective_idx ON consent_records (subject_id, session_id, purpose, seq);
CREATE INDEX consent_records_session_idx ON consent_records (session_id, purpose, seq);

-- +goose StatementBegin
-- Insert-only: blocking UPDATE/DELETE keeps the ledger tamper-evident at the DB
-- boundary; the hash chain catches row replacement (see consent.VerifyChain).
CREATE OR REPLACE FUNCTION consent_records_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'consent_records is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER consent_records_no_update BEFORE UPDATE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION consent_records_immutable();
CREATE TRIGGER consent_records_no_delete BEFORE DELETE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION consent_records_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS consent_records_no_delete ON consent_records;
DROP TRIGGER IF EXISTS consent_records_no_update ON consent_records;
DROP FUNCTION IF EXISTS consent_records_immutable();
DROP TABLE IF EXISTS consent_records;
