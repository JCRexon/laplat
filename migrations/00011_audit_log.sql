-- +goose Up
-- The audit log: a tamper-evident trail of privileged actions (who did what to
-- whom, when). State columns answer "what is true now"; this answers "what
-- happened" — the question a Decree 147 / PDPL regulator asks about identity and
-- moderation actions. See AUDIT.md.
--
-- The row is append-only, hash-chained, and server-signed. Each entry is written
-- in the SAME transaction as the state change it records, so there is no action
-- without its trail. seq is the chain's total order; entry_hash chains to
-- prev_hash and is ed25519 signed (signing_key_id keeps verification rotation-
-- safe). Immutability is enforced below by a trigger, not merely by convention.
CREATE TABLE audit_log (
    seq            bigserial PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor_id       text,                       -- authenticated subject; null for system actions
    actor_role     text NOT NULL,              -- authority exercised: platform_moderator | self | system
    action         text NOT NULL,              -- e.g. 'user.suspended', 'instructor.granted'
    target_type    text NOT NULL,              -- e.g. 'user', 'session'
    target_id      text NOT NULL,
    metadata       jsonb NOT NULL DEFAULT '{}',
    prev_hash      bytea NOT NULL,             -- entry_hash of seq-1 (32 zero bytes at genesis)
    entry_hash     bytea NOT NULL,             -- sha256 over the canonical SignedPayload (incl prev_hash)
    signing_key_id text NOT NULL,
    signature      bytea NOT NULL
);

-- Query the trail for one target (the common forensic lookup).
CREATE INDEX audit_log_target_idx ON audit_log (target_type, target_id, seq);
-- And by actor (what did this moderator do).
CREATE INDEX audit_log_actor_idx ON audit_log (actor_id, seq);

-- +goose StatementBegin
-- Immutability: the audit log is insert-only. Any UPDATE or DELETE — even by a
-- privileged user — raises, so history cannot be rewritten in place. (Row
-- replacement is separately defeated by the hash chain, which VerifyAuditChain
-- checks.)
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log;
DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
DROP FUNCTION IF EXISTS audit_log_immutable();
DROP TABLE IF EXISTS audit_log;
