-- +goose Up
-- Two defence-in-depth refinements from the schema review.

-- (1) Identity-downgrade re-validation. The activation trigger only guards the
-- transition INTO active; nothing reacted when a verified adult identity was
-- later revoked, so a user could stay active after losing verification. This
-- trigger closes that gap: when an identity is downgraded out of the
-- verified-adult state, any currently-active owner is suspended AND their
-- token_version is bumped (revoke-all), so outstanding access tokens stop
-- validating immediately rather than living out their TTL. The app is still
-- expected to own this transition; the trigger is the backstop.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_identity_downgrade() RETURNS trigger AS $$
BEGIN
    IF NOT (NEW.is_adult AND NEW.verification_status = 'verified') THEN
        UPDATE users
        SET status = 'suspended',
            token_version = token_version + 1
        WHERE id = NEW.user_id AND status = 'active';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_enforce_identity_downgrade
    AFTER UPDATE OF verification_status, is_adult ON identity_vault
    FOR EACH ROW EXECUTE FUNCTION enforce_identity_downgrade();

-- (2) Direct-session cap now counts only PRESENT participants (left_at IS
-- NULL). The cap is on concurrent occupancy of a 1:1 room, so a peer who left
-- should free their slot for a replacement; counting historical rows wrongly
-- blocked re-admission. The row lock (concurrency safety) is retained.
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
        FROM session_participants
        WHERE session_id = NEW.session_id AND left_at IS NULL;
        IF participant_count >= 2 THEN
            RAISE EXCEPTION 'direct session % is limited to 2 participants', NEW.session_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- Restore the cap that counts all rows (pre-00004 semantics).
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
DROP TRIGGER IF EXISTS trg_enforce_identity_downgrade ON identity_vault;
DROP FUNCTION IF EXISTS enforce_identity_downgrade();
