-- First-party email-OTP login. Login factor only; never adult eKYC.

-- name: GetEmailIdentity :one
SELECT email, user_id, created_at, last_login
FROM email_identities
WHERE email = $1;

-- name: LinkEmailIdentity :exec
INSERT INTO email_identities (email, user_id)
VALUES ($1, $2);

-- name: TouchEmailLogin :exec
UPDATE email_identities SET last_login = now()
WHERE email = $1;

-- name: CreateLoginChallenge :exec
INSERT INTO login_challenges (id, email, code_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetActiveLoginChallenge :one
-- The newest unconsumed, unexpired challenge for an email.
SELECT id, email, code_hash, attempts, expires_at, consumed_at, created_at
FROM login_challenges
WHERE email = $1 AND consumed_at IS NULL AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1;

-- name: IncrementLoginChallengeAttempts :exec
UPDATE login_challenges SET attempts = attempts + 1 WHERE id = $1;

-- name: ConsumeLoginChallenge :exec
UPDATE login_challenges SET consumed_at = now() WHERE id = $1;
