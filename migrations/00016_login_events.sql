-- +goose Up
-- Authentication activity: one row per successful sign-in (or factor binding),
-- so a user can review recent account access on their security page. Operational
-- telemetry, not legal evidence — plain INSERT, no hash chain.
--
-- We record the method and time only. The client IP is intentionally NOT stored
-- here: authd sits behind the SvelteKit BFF, so the only address it observes is
-- the BFF's own. Capturing the real client IP would require the BFF to forward
-- it and is deferred until that plumbing exists.
CREATE TABLE login_events (
    id         text        NOT NULL PRIMARY KEY,
    user_id    text        NOT NULL REFERENCES users(id),
    method     text        NOT NULL,            -- 'email' | 'phone' | 'google' | 'apple' | 'zalo'
    created_at timestamptz NOT NULL DEFAULT now()
);

-- "Show me my recent sign-ins" — newest first per user.
CREATE INDEX login_events_user_idx ON login_events (user_id, created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS login_events_user_idx;
DROP TABLE IF EXISTS login_events;
