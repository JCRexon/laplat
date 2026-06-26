-- +goose Up
-- Class enrollment roster: which students have joined which classes.
-- Mutable (enroll = INSERT, unenroll = DELETE) — unlike the consent or audit
-- ledgers this is operational state, not legal evidence. Payments and
-- entitlements are gated here once the payment system is built.
CREATE TABLE class_members (
    class_id    text        NOT NULL REFERENCES classes(id),
    user_id     text        NOT NULL REFERENCES users(id),
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (class_id, user_id)
);

-- For "my classes" lookup — student asks "what have I enrolled in?".
CREATE INDEX class_members_user_idx ON class_members (user_id);

-- +goose Down
DROP INDEX IF EXISTS class_members_user_idx;
DROP TABLE IF EXISTS class_members;
