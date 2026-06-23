-- Federated (OIDC) login identities. Login factor only; never adult eKYC.

-- name: GetFederatedIdentity :one
SELECT provider, subject, user_id, created_at, last_login
FROM federated_identities
WHERE provider = $1 AND subject = $2;

-- name: LinkFederatedIdentity :exec
INSERT INTO federated_identities (provider, subject, user_id)
VALUES ($1, $2, $3);

-- name: TouchFederatedLogin :exec
UPDATE federated_identities SET last_login = now()
WHERE provider = $1 AND subject = $2;
