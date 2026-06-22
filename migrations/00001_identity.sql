-- +goose Up
-- Slice 1 — identity & accounts (stream A).
-- Realises contracts §1 (token spine) and the security-first decisions
-- recorded in docs/data-model.md. Adults only; PII isolated in identity_vault.

CREATE TABLE users (
    id                    text PRIMARY KEY,                 -- ULID, no PII
    handle                text UNIQUE NOT NULL,
    display_name          text NOT NULL,
    bio                   text,
    locale                text NOT NULL DEFAULT 'vi',
    status                text NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','active','suspended','deleted')),
    can_instruct          boolean NOT NULL DEFAULT false,   -- backs caps:can_instruct
    is_platform_moderator boolean NOT NULL DEFAULT false,   -- backs caps:platform_moderator
    token_version         integer NOT NULL DEFAULT 1,       -- bump = revoke-all (A-5 / token tver)
    created_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);

-- The ONLY place raw identity PII lives: encrypted, access-restricted,
-- retained per Decree 147 (>= 24 months) then erased (G-1, A-6).
CREATE TABLE identity_vault (
    user_id             text PRIMARY KEY REFERENCES users(id),
    verification_status text NOT NULL DEFAULT 'none'
                        CHECK (verification_status IN ('none','pending','verified')),
    is_adult            boolean NOT NULL DEFAULT false,     -- >= 18, gates activation
    provider_ref        text,        -- opaque eKYC reference, NOT the raw ID
    full_name_enc       bytea,
    dob_enc             bytea,
    phone_hash          bytea,
    email_enc           bytea,
    verified_at         timestamptz,
    retain_until        timestamptz
);

-- Adult gate (defence in depth, item 6): a user may only become 'active' when
-- a verified adult identity exists. The app enforces this too; the trigger
-- makes it impossible to bypass at the DB boundary.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_adult_activation() RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'active' THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_vault v
            WHERE v.user_id = NEW.id
              AND v.is_adult = true
              AND v.verification_status = 'verified'
        ) THEN
            RAISE EXCEPTION 'cannot activate user %: requires verified adult identity', NEW.id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_enforce_adult_activation
    BEFORE INSERT OR UPDATE OF status ON users
    FOR EACH ROW EXECUTE FUNCTION enforce_adult_activation();

-- Refresh tokens: opaque, hashed at rest, rotated on use with reuse detection.
-- Presenting a token that is already revoked or replaced => reuse => the room
-- service revokes the whole family_id (theft signal). Access tokens carry no
-- grants (contracts §1).
CREATE TABLE refresh_tokens (
    id             text PRIMARY KEY,                 -- ULID
    user_id        text NOT NULL REFERENCES users(id),
    family_id      text NOT NULL,                    -- rotation chain
    token_hash     bytea NOT NULL,                   -- hash, never the token
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    replaced_by_id text REFERENCES refresh_tokens(id),
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

-- Single-token revocation: access-token jti denylist, pruned after natural exp.
CREATE TABLE revoked_tokens (
    jti        text PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tos_acceptances (
    user_id        text NOT NULL REFERENCES users(id),
    tos_version    text NOT NULL,
    adult_attested boolean NOT NULL,                 -- explicit 18+ attestation
    accepted_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tos_version)
);

-- +goose Down
DROP TABLE IF EXISTS tos_acceptances;
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS refresh_tokens;
DROP TRIGGER IF EXISTS trg_enforce_adult_activation ON users;
DROP FUNCTION IF EXISTS enforce_adult_activation();
DROP TABLE IF EXISTS identity_vault;
DROP TABLE IF EXISTS users;
