-- +goose Up
-- Allow 'zalo' as a federated-login provider. Zalo is the dominant messaging app
-- in Vietnam; "Sign in with Zalo" lowers the sign-up barrier for VN users. Like
-- Google/Apple it is a LOGIN factor only (proves account control, not adulthood)
-- and links by (provider, subject), never email.
ALTER TABLE federated_identities DROP CONSTRAINT federated_identities_provider_check;
ALTER TABLE federated_identities ADD CONSTRAINT federated_identities_provider_check
    CHECK (provider IN ('google','apple','zalo'));

-- +goose Down
ALTER TABLE federated_identities DROP CONSTRAINT federated_identities_provider_check;
ALTER TABLE federated_identities ADD CONSTRAINT federated_identities_provider_check
    CHECK (provider IN ('google','apple'));
