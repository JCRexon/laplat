-- +goose Up
-- Phone one-time-code factor. It is BOTH a login factor (sign in by phone) and
-- the basis of the 'phone_verified' assurance tier — the Decree 147 interaction
-- floor (a verified VN phone is required to post/comment/livestream). Reaching
-- the phone_verified tier additionally requires the 18+ self-attestation; a
-- phone binding alone proves identity-control, not adulthood.
--
-- phone_identities stores the verified phone in E.164 form. Unlike eKYC PII, a
-- phone number is exactly what Decree 147 requires providers to retain as the
-- account-authentication record, so it is held directly (not hashed).
CREATE TABLE phone_identities (
    phone      text NOT NULL PRIMARY KEY, -- E.164, e.g. +8490...
    user_id    text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login timestamptz
);
CREATE INDEX idx_phone_identities_user ON phone_identities(user_id);

-- phone_challenges mirrors login_challenges: a single-use, short-lived,
-- attempt-limited OTP, stored only as a SHA-256 hash.
CREATE TABLE phone_challenges (
    id          text NOT NULL PRIMARY KEY,
    phone       text NOT NULL,
    code_hash   bytea NOT NULL,
    attempts    int NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_phone_challenges_phone_created ON phone_challenges(phone, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS phone_challenges;
DROP TABLE IF EXISTS phone_identities;
