-- Terms-of-Service acceptances, including the explicit 18+ self-attestation that
-- backs the 'declared' identity-assurance tier.

-- name: AcceptToS :exec
-- Idempotent per (user, version): re-accepting updates the attestation/time.
INSERT INTO tos_acceptances (user_id, tos_version, adult_attested)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, tos_version)
DO UPDATE SET adult_attested = EXCLUDED.adult_attested, accepted_at = now();

-- name: HasAdultAttestation :one
-- True if the user has self-attested 18+ under any ToS version.
SELECT EXISTS (
    SELECT 1 FROM tos_acceptances
    WHERE user_id = $1 AND adult_attested = true
);
