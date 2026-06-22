//go:build integration

// Package dbtest boots a throwaway local PostgreSQL cluster for integration
// tests and applies the goose migrations to it. It shells out to the installed
// Postgres server binaries and `psql` (stdlib os/exec only — no Go DB driver),
// so it adds zero dependencies. Tests that need a typed driver/sqlc come with
// the DB layer.
//
// Postgres refuses to run as root. When the test process is root (e.g. some
// container/CI setups) the server binaries are run as the unprivileged
// `postgres` system user via sudo, and the cluster directory is owned by that
// user. When the test runs as a normal user, everything runs directly.
package dbtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// runAsUser is the unprivileged account used when the test process is root.
const runAsUser = "postgres"

// PG is a running ephemeral cluster bound to a unix socket in a temp dir.
type PG struct {
	t       *testing.T
	bin     string
	socket  string
	workDir string
	dbName  string
	asUser  string // non-empty => wrap commands in `sudo -u <asUser>`
}

// New initialises, starts, and migrates a throwaway cluster, registering
// cleanup with t.
func New(t *testing.T) *PG {
	t.Helper()
	pg := &PG{t: t, bin: pgBinDir(t), dbName: "app"}
	if os.Geteuid() == 0 {
		pg.asUser = runAsUser
	}

	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	pg.socket = filepath.Join(dir, "sock")
	pg.workDir = filepath.Join(dir, "work")
	mustMkdir(t, pg.socket)
	mustMkdir(t, pg.workDir)

	// When running the server as another user, that user must own the cluster
	// tree and be able to traverse into it.
	if pg.asUser != "" {
		mustChmod(t, 0o755, dir, filepath.Dir(dir))
		mustRun(t, "chown", "-R", pg.asUser, dir)
	}

	pg.run(t, filepath.Join(pg.bin, "initdb"),
		"-D", dataDir, "-U", "postgres", "-A", "trust", "--no-locale", "-E", "UTF8")

	logFile := filepath.Join(dir, "pg.log")
	if pg.asUser != "" {
		mustRun(t, "chown", pg.asUser, dir) // log file is created here by pg_ctl
	}
	pg.run(t, filepath.Join(pg.bin, "pg_ctl"),
		"-D", dataDir, "-l", logFile, "-w",
		"-o", "-k "+pg.socket+" -h ''",
		"start")
	t.Cleanup(func() {
		_ = pg.command(filepath.Join(pg.bin, "pg_ctl"), "-D", dataDir, "-m", "immediate", "stop").Run()
	})

	pg.run(t, "psql", "-h", pg.socket, "-U", "postgres", "-d", "postgres",
		"-v", "ON_ERROR_STOP=1", "-q", "-c", "CREATE DATABASE app;")
	pg.applyMigrations(t)
	return pg
}

// ConnString is a libpq DSN for connecting a Go driver (pgx) to this cluster
// over its unix socket. Used by the data-access layer's integration tests.
func (p *PG) ConnString() string {
	return "host=" + p.socket + " user=postgres dbname=" + p.dbName
}

// Exec runs SQL and returns an error if Postgres reports one (ON_ERROR_STOP).
// Tests use this to assert that a constraint or trigger REJECTS bad input.
func (p *PG) Exec(sql string) error {
	out, err := p.command("psql", "-h", p.socket, "-U", "postgres", "-d", p.dbName,
		"-v", "ON_ERROR_STOP=1", "-q", "-c", sql).CombinedOutput()
	if err != nil {
		return &sqlError{msg: strings.TrimSpace(string(out))}
	}
	return nil
}

// MustExec fails the test if the SQL errors.
func (p *PG) MustExec(sql string) {
	p.t.Helper()
	if err := p.Exec(sql); err != nil {
		p.t.Fatalf("unexpected SQL error: %v\nSQL: %s", err, sql)
	}
}

// applyMigrations runs the Up section of each goose migration in order. The
// goose markers are SQL comments; we feed only the text between `-- +goose Up`
// and `-- +goose Down` so the Down section never runs.
func (p *PG) applyMigrations(t *testing.T) {
	t.Helper()
	root := migrationsDir(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		up := upSection(string(raw))
		if strings.TrimSpace(up) == "" {
			t.Fatalf("%s: empty Up section", f)
		}
		tmp := filepath.Join(p.workDir, f)
		if err := os.WriteFile(tmp, []byte(up), 0o644); err != nil {
			t.Fatalf("write tmp migration: %v", err)
		}
		p.run(t, "psql", "-h", p.socket, "-U", "postgres", "-d", p.dbName,
			"-v", "ON_ERROR_STOP=1", "-q", "-f", tmp)
	}
}

// command builds an *exec.Cmd, wrapping it in `sudo -u <asUser>` when set.
func (p *PG) command(name string, args ...string) *exec.Cmd {
	if p.asUser != "" {
		return exec.Command("sudo", append([]string{"-u", p.asUser, name}, args...)...)
	}
	return exec.Command(name, args...)
}

// run executes a command and fails the test on error.
func (p *PG) run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := p.command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func upSection(s string) string {
	up := s
	if i := strings.Index(up, "-- +goose Up"); i >= 0 {
		up = up[i+len("-- +goose Up"):]
	}
	if i := strings.Index(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	return up
}

func pgBinDir(t *testing.T) string {
	t.Helper()
	matches, _ := filepath.Glob("/usr/lib/postgresql/*/bin/initdb")
	if len(matches) > 0 {
		sort.Strings(matches)
		return filepath.Dir(matches[len(matches)-1])
	}
	if p, err := exec.LookPath("initdb"); err == nil {
		return filepath.Dir(p)
	}
	t.Skip("dbtest: no Postgres server binaries (initdb) found")
	return ""
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "migrations")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("dbtest: could not locate module root / migrations dir")
		}
		dir = parent
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustChmod(t *testing.T, mode os.FileMode, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

type sqlError struct{ msg string }

func (e *sqlError) Error() string { return e.msg }
