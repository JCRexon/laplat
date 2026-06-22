-- Access-token revocation state (A-5): the parts of validation the stateless
-- signature check cannot answer. Backs token.RevocationStore.

-- name: IsAccessTokenRevoked :one
SELECT EXISTS (
    SELECT 1 FROM revoked_tokens WHERE jti = $1
);

-- name: RevokeAccessToken :exec
-- Single-token revocation: denylist a jti until its natural expiry. Idempotent.
INSERT INTO revoked_tokens (jti, expires_at)
VALUES ($1, $2)
ON CONFLICT (jti) DO NOTHING;

-- name: CurrentTokenVersion :one
SELECT token_version FROM users WHERE id = $1;

-- name: BumpTokenVersion :one
-- Revoke-all for a user: every outstanding access token (tver < new) is now
-- superseded. Returns the new version.
UPDATE users SET token_version = token_version + 1
WHERE id = $1
RETURNING token_version;
