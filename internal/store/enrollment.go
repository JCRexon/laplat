package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// EnrollClass adds a user to a class roster. Idempotent — enrolling an already
// enrolled user is a no-op (ON CONFLICT DO NOTHING).
func (s *Store) EnrollClass(ctx context.Context, classID, userID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO class_members (class_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, classID, userID)
	return err
}

// UnenrollClass removes a user from a class roster. A no-op when the user is
// not enrolled.
func (s *Store) UnenrollClass(ctx context.Context, classID, userID string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM class_members WHERE class_id = $1 AND user_id = $2`,
		classID, userID)
	return err
}

// CountClassMembers returns the number of users enrolled in a class — the roster
// size the capacity gate checks.
func (s *Store) CountClassMembers(ctx context.Context, classID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM class_members WHERE class_id = $1`, classID).Scan(&n)
	return n, err
}

// ClassCapacity returns a class's enrollment cap (0 = unlimited) and whether the
// class exists. A one-column read so the sqlc-generated Class struct is untouched.
func (s *Store) ClassCapacity(ctx context.Context, classID string) (int, bool, error) {
	var cap int
	err := s.pool.QueryRow(ctx, `SELECT capacity FROM classes WHERE id = $1`, classID).Scan(&cap)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return cap, true, nil
}

// SetClassCapacity sets a class's enrollment cap (0 = unlimited).
func (s *Store) SetClassCapacity(ctx context.Context, classID string, capacity int) error {
	_, err := s.pool.Exec(ctx, `UPDATE classes SET capacity = $2 WHERE id = $1`, classID, capacity)
	return err
}

// IsEnrolled reports whether the user is a member of the class.
func (s *Store) IsEnrolled(ctx context.Context, classID, userID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM class_members WHERE class_id = $1 AND user_id = $2
		)`, classID, userID).Scan(&exists)
	return exists, err
}

// EnrolledClassesWithDetails returns full Class rows for all classes the user
// is enrolled in, newest enrollment first.
func (s *Store) EnrolledClassesWithDetails(ctx context.Context, userID string) ([]Class, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.instructor_id, c.title, c.description, c.status, c.created_at
		FROM classes c
		JOIN class_members m ON m.class_id = c.id
		WHERE m.user_id = $1
		ORDER BY m.enrolled_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Class
	for rows.Next() {
		var c Class
		if err := rows.Scan(&c.ID, &c.InstructorID, &c.Title, &c.Description, &c.Status, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EnrolledClassIDs returns the class IDs the user is enrolled in, newest
// enrollment first. Lighter than EnrolledClassesWithDetails when only IDs are
// needed (e.g. building an enrolled-set for the catalog view).
func (s *Store) EnrolledClassIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT class_id FROM class_members
		WHERE user_id = $1 ORDER BY enrolled_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if errors.Is(rows.Err(), pgx.ErrNoRows) {
		return nil, nil
	}
	return out, rows.Err()
}
