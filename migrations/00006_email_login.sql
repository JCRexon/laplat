-- +goose Up
-- First-party email login factor: one-time code (OTP) sign-in. Like the
-- federated factor, this is a LOGIN factor only — it proves control of an email
-- address, NOT adult identity. An email-OTP user starts 'pending' and cannot go
-- 'active' until eKYC verifies them (identity_vault + triggers, unchanged).
--
-- email_identities is the linkage: a normalized email maps to exactly one local
-- user. Unlike OIDC (where we refuse to link by an IdP-asserted email), here we
-- DO key on email — because this factor itself proves control of that mailbox
-- by delivering a code to it. It is a separate namespace from federated_identities
-- and the two are never auto-merged.
CREATE TABLE email_identities (
    email      text NOT NULL PRIMARY KEY, -- stored normalized (lowercased)
    user_id    text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login timestamptz
);
CREATE INDEX idx_email_identities_user ON email_identities(user_id);

-- login_challenges holds in-flight OTP codes. The code is stored only as a
-- SHA-256 hash (the cleartext lives solely in the delivered email). A challenge
-- is single-use (consumed_at), short-lived (expires_at), and attempt-limited
-- (attempts, enforced in the service) to bound guessing of the 6-digit code.
CREATE TABLE login_challenges (
    id         text NOT NULL PRIMARY KEY,
    email      text NOT NULL,
    code_hash  bytea NOT NULL,
    attempts   int NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Latest-active-challenge lookup and resend cooldown both scan by email/time.
CREATE INDEX idx_login_challenges_email_created ON login_challenges(email, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS login_challenges;
DROP TABLE IF EXISTS email_identities;
