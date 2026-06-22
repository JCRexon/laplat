-- +goose Up
-- DB-layer hardening for Slice 1. Closes gaps found while reviewing the
-- identity (00001) and sessions (00002) schema:
--   * the direct-session cap (C-4 backstop) was racy under concurrency;
--   * handle uniqueness was case-sensitive (impersonation / squatting);
--   * refresh-token rotation/reuse lookups were unindexed and hashes could
--     duplicate;
--   * the expiry-based pruning sweeps had no supporting index.

-- C-4 backstop, now concurrency-safe. The original trigger counted
-- participants without serialising concurrent inserts, so two transactions
-- could each see one participant and both admit a second — yielding three.
-- Taking a row lock on the parent sessions row first forces concurrent
-- admissions to the SAME session to take turns, so the count is always
-- authoritative. (Locking happens on every participant insert; the cap itself
-- is still only enforced for kind='direct'.)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_direct_session_cap() RETURNS trigger AS $$
DECLARE
    session_kind text;
    participant_count integer;
BEGIN
    SELECT kind INTO session_kind FROM sessions
        WHERE id = NEW.session_id FOR UPDATE;
    IF session_kind = 'direct' THEN
        SELECT count(*) INTO participant_count
        FROM session_participants WHERE session_id = NEW.session_id;
        IF participant_count >= 2 THEN
            RAISE EXCEPTION 'direct session % is limited to 2 participants', NEW.session_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Case-insensitive handle uniqueness. Drop the implicit UNIQUE constraint that
-- the inline column definition created and replace it with a functional unique
-- index, so 'An' and 'an' cannot both be claimed.
ALTER TABLE users DROP CONSTRAINT users_handle_key;
CREATE UNIQUE INDEX idx_users_handle_lower ON users (lower(handle));

-- Refresh-token rotation is keyed by the presented token's hash: the lookup
-- must be indexed, and a hash must map to at most one row — a duplicate is a
-- bug or an attack, not a valid state.
CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Pruning sweeps both token tables by natural expiry.
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_revoked_tokens_expires;
DROP INDEX IF EXISTS idx_refresh_tokens_expires;
DROP INDEX IF EXISTS idx_refresh_tokens_token_hash;
DROP INDEX IF EXISTS idx_users_handle_lower;
ALTER TABLE users ADD CONSTRAINT users_handle_key UNIQUE (handle);
-- Restore the pre-hardening (racy) cap function so Down is a true inverse.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_direct_session_cap() RETURNS trigger AS $$
DECLARE
    session_kind text;
    participant_count integer;
BEGIN
    SELECT kind INTO session_kind FROM sessions WHERE id = NEW.session_id;
    IF session_kind = 'direct' THEN
        SELECT count(*) INTO participant_count
        FROM session_participants WHERE session_id = NEW.session_id;
        IF participant_count >= 2 THEN
            RAISE EXCEPTION 'direct session % is limited to 2 participants', NEW.session_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
