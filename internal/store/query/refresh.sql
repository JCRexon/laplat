-- Refresh-token rotation chain (A-5). Tokens are opaque and stored only as a
-- hash; rotation is single-use with reuse detection at the family level.

-- name: IssueRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetRefreshTokenByHashForUpdate :one
-- Locks the row for the duration of the rotation transaction so a token
-- presented concurrently cannot rotate twice (serialises reuse detection).
SELECT id, user_id, family_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at
FROM refresh_tokens
WHERE token_hash = $1
FOR UPDATE;

-- name: MarkRefreshTokenReplaced :exec
UPDATE refresh_tokens
SET revoked_at = now(), replaced_by_id = $2
WHERE id = $1;

-- name: RevokeRefreshFamily :exec
-- Theft response: revoke every live token in the rotation chain at once.
UPDATE refresh_tokens
SET revoked_at = now()
WHERE family_id = $1 AND revoked_at IS NULL;

-- name: GetFamilyByHash :one
-- Resolves the rotation family a presented token belongs to (any state), so a
-- logout can revoke the whole chain.
SELECT family_id FROM refresh_tokens WHERE token_hash = $1;
