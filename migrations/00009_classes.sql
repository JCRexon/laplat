-- +goose Up
-- Classes: an instructor's course definition. A live "class" session
-- (sessions.kind='class') is an instance OF a class, so we can now add the
-- foreign key that migration 00002 deferred. Creating/owning a class requires
-- the can_instruct capability (enforced in the service); the FK guarantees a
-- class session always points at a real, owned class.
CREATE TABLE classes (
    id            text NOT NULL PRIMARY KEY,
    instructor_id text NOT NULL REFERENCES users(id),
    title         text NOT NULL,
    description   text NOT NULL DEFAULT '',
    status        text NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft','published','archived')),
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_classes_instructor ON classes(instructor_id);

-- Wire the deferred foreign key from sessions to classes.
ALTER TABLE sessions
    ADD CONSTRAINT sessions_class_id_fkey
    FOREIGN KEY (class_id) REFERENCES classes(id);

-- +goose Down
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_class_id_fkey;
DROP TABLE IF EXISTS classes;
