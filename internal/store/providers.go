package store

import "context"

// ListAuthProviders returns the registered federated-login provider names. The
// set lives in the auth_providers reference table (Brick 3), so it is data, not
// a hardcoded allowlist; the federated_identities FK enforces it at write time
// and startup validates configured connectors against it.
func (s *Store) ListAuthProviders(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT name FROM auth_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
