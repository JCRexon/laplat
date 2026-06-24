-- Sessions and their participants. The kind/class_id coherence CHECK and the
-- direct-session participant cap are enforced DB-side; these queries surface
-- those guarantees rather than re-implementing them.

-- name: CreateSession :one
INSERT INTO sessions (id, kind, class_id, livekit_room, scheduled_start)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, kind, class_id, livekit_room, status, scheduled_start, started_at, ended_at, created_at;

-- name: GetSession :one
SELECT id, kind, class_id, livekit_room, status, scheduled_start, started_at, ended_at, created_at
FROM sessions WHERE id = $1;

-- name: StartSession :exec
UPDATE sessions SET status = 'live', started_at = now() WHERE id = $1;

-- name: EndSession :exec
UPDATE sessions SET status = 'ended', ended_at = now() WHERE id = $1;

-- name: AddParticipant :exec
-- Subject to trg_enforce_direct_session_cap for direct sessions.
INSERT INTO session_participants (session_id, user_id, role)
VALUES ($1, $2, $3);

-- name: RemoveParticipant :exec
UPDATE session_participants SET left_at = now()
WHERE session_id = $1 AND user_id = $2 AND left_at IS NULL;

-- name: ListSessionsByClass :many
-- A class's sessions for discovery: soonest-scheduled first, then newest.
SELECT id, kind, class_id, livekit_room, status, scheduled_start, started_at, ended_at, created_at
FROM sessions WHERE class_id = $1
ORDER BY scheduled_start ASC NULLS LAST, created_at DESC
LIMIT 100;

-- name: ListActiveParticipants :many
SELECT session_id, user_id, role, joined_at, left_at
FROM session_participants
WHERE session_id = $1 AND left_at IS NULL
ORDER BY joined_at;
