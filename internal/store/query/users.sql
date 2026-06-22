-- Users: opaque-id accounts, no PII (PII lives in identity_vault). Activation
-- is gated DB-side by the verified-adult trigger; these queries never bypass it.

-- name: CreateUser :one
INSERT INTO users (id, handle, display_name, locale, can_instruct)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, handle, display_name, bio, locale, status, can_instruct, is_platform_moderator, token_version, created_at, deleted_at;

-- name: GetUser :one
SELECT id, handle, display_name, bio, locale, status, can_instruct, is_platform_moderator, token_version, created_at, deleted_at
FROM users WHERE id = $1;

-- name: GetUserByHandle :one
-- Login lookup. Case-insensitive (matches the lower(handle) unique index) and
-- excludes soft-deleted accounts.
SELECT id, handle, display_name, bio, locale, status, can_instruct, is_platform_moderator, token_version, created_at, deleted_at
FROM users WHERE lower(handle) = lower($1) AND deleted_at IS NULL;

-- name: ActivateUser :exec
-- Subject to trg_enforce_adult_activation: fails unless a verified adult
-- identity exists for the user.
UPDATE users SET status = 'active' WHERE id = $1;

-- name: SuspendUser :exec
UPDATE users SET status = 'suspended' WHERE id = $1;

-- name: SoftDeleteUser :exec
UPDATE users SET status = 'deleted', deleted_at = now() WHERE id = $1;
