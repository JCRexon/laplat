-- Classes: instructor course definitions.

-- name: CreateClass :one
INSERT INTO classes (id, instructor_id, title, description)
VALUES ($1, $2, $3, $4)
RETURNING id, instructor_id, title, description, status, created_at;

-- name: GetClass :one
SELECT id, instructor_id, title, description, status, created_at
FROM classes WHERE id = $1;

-- name: ListClassesByInstructor :many
SELECT id, instructor_id, title, description, status, created_at
FROM classes WHERE instructor_id = $1
ORDER BY created_at DESC;

-- name: UpdateClassStatus :exec
UPDATE classes SET status = $2 WHERE id = $1;
