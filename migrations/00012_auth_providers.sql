-- +goose Up
-- Brick 3: make the federated-login provider set a reference table instead of a
-- CHECK constraint baked into federated_identities. Adding a provider then is a
-- data INSERT into auth_providers (plus connector config), not an ALTER of a
-- CHECK constraint and an edit to a hardcoded Go allowlist. See
-- AUTH-EXTENSIBILITY.md (Brick 3).
CREATE TABLE auth_providers (
    name       text PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('oidc','oauth2')), -- redirect protocol family
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Seed the providers the previous CHECK constraint hard-coded.
INSERT INTO auth_providers (name, kind) VALUES
    ('google', 'oidc'),
    ('apple',  'oidc'),
    ('zalo',   'oauth2');

-- Replace the value-list CHECK with a foreign key to the reference table: the
-- set of valid providers now lives in data, and integrity is still enforced.
ALTER TABLE federated_identities DROP CONSTRAINT federated_identities_provider_check;
ALTER TABLE federated_identities ADD CONSTRAINT federated_identities_provider_fk
    FOREIGN KEY (provider) REFERENCES auth_providers(name);

-- +goose Down
ALTER TABLE federated_identities DROP CONSTRAINT federated_identities_provider_fk;
ALTER TABLE federated_identities ADD CONSTRAINT federated_identities_provider_check
    CHECK (provider IN ('google','apple','zalo'));
DROP TABLE auth_providers;
