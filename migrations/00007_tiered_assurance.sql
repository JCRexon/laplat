-- +goose Up
-- Tiered identity assurance. Previously an account could only become 'active'
-- with a verified-adult eKYC identity. That made full eKYC a barrier to entry
-- for every feature. We now recognise a middle tier: a self-attested adult (an
-- adult_attested row in tos_acceptances) may become active and use general
-- features; eKYC ('verified') is reserved for high-risk actions (instructing,
-- 1:1 rooms, payments), enforced at the point of use via the token's idv tier.
--
-- Two triggers are relaxed to accept EITHER basis (verified adult OR adult
-- attestation):

-- (1) Activation gate: allow active when verified-adult OR self-attested-adult.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_adult_activation() RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'active' THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_vault v
            WHERE v.user_id = NEW.id
              AND v.is_adult = true
              AND v.verification_status = 'verified'
        ) AND NOT EXISTS (
            SELECT 1 FROM tos_acceptances t
            WHERE t.user_id = NEW.id
              AND t.adult_attested = true
        ) THEN
            RAISE EXCEPTION 'cannot activate user %: requires verified adult identity or adult attestation', NEW.id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- (2) Identity-downgrade backstop: only suspend an active user on eKYC
-- revocation if they ALSO lack an adult attestation. A self-attested adult who
-- loses (or never had) eKYC drops to the 'declared' tier rather than being
-- suspended outright; a user with no basis at all is still suspended + revoked.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_identity_downgrade() RETURNS trigger AS $$
BEGIN
    IF NOT (NEW.is_adult AND NEW.verification_status = 'verified')
       AND NOT EXISTS (
           SELECT 1 FROM tos_acceptances t
           WHERE t.user_id = NEW.user_id
             AND t.adult_attested = true
       ) THEN
        UPDATE users
        SET status = 'suspended',
            token_version = token_version + 1
        WHERE id = NEW.user_id AND status = 'active';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- Restore the verified-adult-only forms.
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_identity_downgrade() RETURNS trigger AS $$
BEGIN
    IF NOT (NEW.is_adult AND NEW.verification_status = 'verified') THEN
        UPDATE users
        SET status = 'suspended',
            token_version = token_version + 1
        WHERE id = NEW.user_id AND status = 'active';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
