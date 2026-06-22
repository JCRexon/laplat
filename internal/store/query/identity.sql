-- identity_vault: the only place identity PII lives (encrypted at rest). These
-- queries write verification *state* and opaque references; raw PII columns
-- (full_name_enc, dob_enc, ...) are written by the eKYC ingestion path, not
-- here. Retention (retain_until) follows Decree 147 (>= 24 months).

-- name: CreateIdentityRecord :exec
-- Establishes the vault row in its default unverified, non-adult state.
INSERT INTO identity_vault (user_id) VALUES ($1);

-- name: VerifyAdultIdentity :exec
-- Records a successful eKYC: verified adult. This is the state the activation
-- trigger requires before a user may go active.
UPDATE identity_vault
SET verification_status = 'verified',
    is_adult = true,
    provider_ref = $2,
    verified_at = now(),
    retain_until = $3
WHERE user_id = $1;

-- name: RevokeIdentityVerification :exec
-- Reverses verification (e.g. eKYC reversal, fraud finding). Defence in depth:
-- a trigger demotes any active user whose identity is revoked this way.
UPDATE identity_vault
SET verification_status = 'none',
    is_adult = false,
    verified_at = NULL
WHERE user_id = $1;

-- name: GetIdentity :one
SELECT user_id, verification_status, is_adult, provider_ref, full_name_enc, dob_enc, phone_hash, email_enc, verified_at, retain_until
FROM identity_vault WHERE user_id = $1;
