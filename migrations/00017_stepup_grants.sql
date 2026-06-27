-- +goose Up
-- Step-up (re-authentication) grants: short-lived proof that a user re-verified
-- their identity (via a fresh OTP) to reach a sensitive surface — currently the
-- consolidated data export. The raw grant token is returned to the BFF once and
-- held in a short-lived httpOnly cookie; only its hash is stored here, the same
-- discipline as refresh tokens and OTP challenges.
CREATE TABLE stepup_grants (
    id         text        NOT NULL PRIMARY KEY,
    user_id    text        NOT NULL REFERENCES users(id),
    token_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Validation looks up by (user, hash); the partial-free index covers it and the
-- expiry sweep.
CREATE INDEX stepup_grants_user_idx ON stepup_grants (user_id);
CREATE INDEX stepup_grants_expiry_idx ON stepup_grants (expires_at);

-- +goose Down
DROP INDEX IF EXISTS stepup_grants_expiry_idx;
DROP INDEX IF EXISTS stepup_grants_user_idx;
DROP TABLE IF EXISTS stepup_grants;
