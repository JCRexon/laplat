-- Phone one-time-code factor: login + the phone_verified assurance tier.

-- name: GetPhoneIdentity :one
SELECT phone, user_id, created_at, last_login
FROM phone_identities
WHERE phone = $1;

-- name: GetPhoneIdentityByUser :one
SELECT phone, user_id, created_at, last_login
FROM phone_identities
WHERE user_id = $1;

-- name: LinkPhoneIdentity :exec
INSERT INTO phone_identities (phone, user_id)
VALUES ($1, $2);

-- name: TouchPhoneLogin :exec
UPDATE phone_identities SET last_login = now()
WHERE phone = $1;

-- name: HasVerifiedPhone :one
SELECT EXISTS (SELECT 1 FROM phone_identities WHERE user_id = $1);

-- name: CreatePhoneChallenge :exec
INSERT INTO phone_challenges (id, phone, code_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetActivePhoneChallenge :one
SELECT id, phone, code_hash, attempts, expires_at, consumed_at, created_at
FROM phone_challenges
WHERE phone = $1 AND consumed_at IS NULL AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1;

-- name: IncrementPhoneChallengeAttempts :exec
UPDATE phone_challenges SET attempts = attempts + 1 WHERE id = $1;

-- name: ConsumePhoneChallenge :exec
UPDATE phone_challenges SET consumed_at = now() WHERE id = $1;
