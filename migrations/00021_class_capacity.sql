-- +goose Up
-- Class capacity: an optional cap on the enrollment roster (the "members-only"
-- sense of a class, orthogonal to the assurance tier). 0 (the default) means
-- unlimited, so existing classes and the current behaviour are unchanged. The
-- enrollment gate enforces it (a soft cap — see internal/class).
ALTER TABLE classes
    ADD COLUMN capacity integer NOT NULL DEFAULT 0
        CHECK (capacity >= 0);

-- +goose Down
ALTER TABLE classes DROP COLUMN IF EXISTS capacity;
