-- +goose Up
-- Federated login identities (OIDC: Sign in with Google / Apple). Links an
-- external provider's stable subject to a local user.
--
-- IMPORTANT: this is a LOGIN factor only. It authenticates control of an
-- external account; it does NOT establish adult identity verification (eKYC),
-- which still gates activation via identity_vault and its triggers. A federated
-- user starts 'pending' and cannot go 'active' until a real adult-KYC step
-- verifies them. We deliberately never auto-link by email (an unverified or
-- recycled email is an account-takeover vector): a (provider, subject) pair
-- maps to exactly one user, and that is the only linkage.
CREATE TABLE federated_identities (
    provider   text NOT NULL CHECK (provider IN ('google','apple')),
    subject    text NOT NULL,            -- OIDC 'sub', stable & unique per provider
    user_id    text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login timestamptz,
    PRIMARY KEY (provider, subject)
);
CREATE INDEX idx_federated_identities_user ON federated_identities(user_id);

-- +goose Down
DROP TABLE IF EXISTS federated_identities;
