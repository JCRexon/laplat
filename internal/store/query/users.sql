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

-- name: UpdateProfile :exec
-- Sets the user-editable profile fields. handle uniqueness is enforced by the
-- lower(handle) unique index (a conflict surfaces as a unique violation).
UPDATE users SET handle = $2, display_name = $3, bio = $4 WHERE id = $1;

-- name: ActivateUser :exec
-- Subject to trg_enforce_adult_activation: fails unless a verified adult
-- identity exists for the user.
UPDATE users SET status = 'active' WHERE id = $1;

-- name: UserExists :one
SELECT EXISTS (SELECT 1 FROM users WHERE id = $1);

-- name: PromoteToModerator :exec
-- Grants the platform-moderator capability (backs caps:platform_moderator).
-- Operator-only path (adminctl); never reachable from user-facing handlers.
UPDATE users SET is_platform_moderator = true WHERE id = $1;

-- name: SuspendUser :exec
UPDATE users SET status = 'suspended' WHERE id = $1;

-- name: SoftDeleteUser :exec
UPDATE users SET status = 'deleted', deleted_at = now() WHERE id = $1;

-- name: CloseAccount :exec
-- Self-service erasure: soft-delete AND revoke-all (bump token_version) in one
-- atomic statement, so outstanding access tokens stop validating immediately.
UPDATE users SET status = 'deleted', deleted_at = now(), token_version = token_version + 1
WHERE id = $1;
