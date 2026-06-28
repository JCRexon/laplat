-- +goose Up
-- Presence checkpoints (ADR-010, stage 2): each row records a Merkle root over a
-- contiguous range of presence_events, anchored by a Vault-signed entry in the
-- global audit_log (audit_seq). This is the index that lets a verifier locate the
-- checkpoint covering a given presence row and rebuild its inclusion proof.
--
-- The cryptographic authority is the signed audit_log entry, not this table:
-- merkle_root is duplicated here for fast lookup, and a verifier cross-checks it
-- against the commitment encoded in the signed entry's target_id (a text column;
-- the root + range live there rather than in the jsonb metadata, which Postgres
-- normalises and so would not round-trip the exact signed bytes). The table is
-- therefore a rebuildable index (derivable from audit_log + presence_events),
-- not a ledger.
CREATE TABLE presence_checkpoints (
    id          text NOT NULL PRIMARY KEY,        -- opaque ULID-shaped id
    from_seq    bigint NOT NULL,                  -- first presence_events.seq covered (inclusive)
    to_seq      bigint NOT NULL,                  -- last presence_events.seq covered (inclusive)
    leaf_count  integer NOT NULL,                 -- number of leaves (rows) in the tree
    merkle_root bytea NOT NULL,                   -- RFC 6962 root over the covered rows
    audit_seq   bigint NOT NULL,                  -- audit_log.seq of the signing entry
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Find the checkpoint covering a given presence seq (from_seq <= seq <= to_seq).
CREATE INDEX presence_checkpoints_range_idx ON presence_checkpoints (from_seq, to_seq);

-- +goose Down
DROP INDEX IF EXISTS presence_checkpoints_range_idx;
DROP TABLE IF EXISTS presence_checkpoints;
