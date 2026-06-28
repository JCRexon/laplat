-- +goose Up
-- Entitlements (ACCESS-MODEL "owned content is entitlement-gated, not tier-gated"):
-- a durable, per-account record that a user owns access to a paid resource. It is
-- the non-provider half of payments — the purchase/charge step (Stripe/VNPay)
-- writes one of these rows on success; until then rows are created by a
-- moderator grant (comp/support) so the gate can be exercised end-to-end.
--
-- This is operational state, not a ledger: it is mutable (revoked_at set on a
-- refund/chargeback). The *payment* that created it is what gets audited. Crucially
-- an entitlement is NEVER revoked by an identity downgrade — you keep what you
-- bought (durability is the whole point of gating on ownership rather than tier).

-- price_cents marks a class as paid. 0 (the default) is the free floor: free
-- classes stay on the tier ladder and need no entitlement, so existing rows and
-- the current behaviour are unchanged. A positive price requires an entitlement.
ALTER TABLE classes
    ADD COLUMN price_cents integer NOT NULL DEFAULT 0
        CHECK (price_cents >= 0);

CREATE TABLE entitlements (
    id            text        NOT NULL PRIMARY KEY,   -- opaque ULID-shaped id
    subject_id    text        NOT NULL REFERENCES users(id),
    resource_type text        NOT NULL CHECK (resource_type IN ('class')),
    resource_id   text        NOT NULL,               -- e.g. a classes.id
    source        text        NOT NULL CHECK (source IN ('purchase', 'grant')),
    price_cents   integer     NOT NULL DEFAULT 0 CHECK (price_cents >= 0), -- what was paid (0 for a grant)
    granted_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,                        -- NULL = perpetual ownership
    revoked_at    timestamptz                         -- set on refund/chargeback/admin revoke
);

-- One *active* entitlement per (subject, resource): a re-grant after a revoke is
-- allowed (a new row), but two live rows for the same ownership are not.
CREATE UNIQUE INDEX entitlements_active_unique
    ON entitlements (subject_id, resource_type, resource_id)
    WHERE revoked_at IS NULL;

-- "My library" lookup — what does this account own?
CREATE INDEX entitlements_subject_idx ON entitlements (subject_id);

-- +goose Down
DROP INDEX IF EXISTS entitlements_subject_idx;
DROP INDEX IF EXISTS entitlements_active_unique;
DROP TABLE IF EXISTS entitlements;
ALTER TABLE classes DROP COLUMN IF EXISTS price_cents;
