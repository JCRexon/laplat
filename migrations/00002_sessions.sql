-- +goose Up
-- Slice 1 — live sessions (stream C). A "session" is the media realisation of
-- a teaching instance; its LiveKit room is a derived handle (entity map).
-- 1:1 calls are kind='direct' with no class (item 6 decision). The classes
-- table and the sessions.class_id foreign key arrive in a later slice.

CREATE TABLE sessions (
    id              text PRIMARY KEY,                 -- ULID; the canonical id
    kind            text NOT NULL CHECK (kind IN ('class','direct')),
    class_id        text,                             -- FK to classes added later
    livekit_room    text NOT NULL UNIQUE,             -- media handle derived from id
    status          text NOT NULL DEFAULT 'scheduled'
                    CHECK (status IN ('scheduled','live','ended')),
    scheduled_start timestamptz,
    started_at      timestamptz,
    ended_at        timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sessions_kind_class CHECK (
        (kind = 'direct' AND class_id IS NULL) OR
        (kind = 'class'  AND class_id IS NOT NULL)
    )
);

-- For direct (1:1) sessions this table doubles as the participant ALLOWLIST:
-- only listed users may obtain a grant for the session. Grant scope is derived
-- from `role` at mint time (A-3); both peers of a direct call get publisher.
CREATE TABLE session_participants (
    session_id text NOT NULL REFERENCES sessions(id),
    user_id    text NOT NULL REFERENCES users(id),
    role       text NOT NULL,                         -- grant authorisation derives from this
    joined_at  timestamptz NOT NULL DEFAULT now(),
    left_at    timestamptz,
    PRIMARY KEY (session_id, user_id)
);

-- Defence in depth (C-4): hard-cap a direct session at 2 participants so a
-- leaked direct grant cannot be used to pack the room. The room service also
-- enforces admission control; this trigger is the backstop.
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

CREATE TRIGGER trg_enforce_direct_session_cap
    BEFORE INSERT ON session_participants
    FOR EACH ROW EXECUTE FUNCTION enforce_direct_session_cap();

-- +goose Down
DROP TRIGGER IF EXISTS trg_enforce_direct_session_cap ON session_participants;
DROP FUNCTION IF EXISTS enforce_direct_session_cap();
DROP TABLE IF EXISTS session_participants;
DROP TABLE IF EXISTS sessions;
