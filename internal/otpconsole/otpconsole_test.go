package otpconsole_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jcrexon/laplat/internal/otpconsole"
)

// The console sender returns nil and writes the code to the log so a dev/E2E
// harness can read it.
func TestSender_LogsCode(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	s := otpconsole.New(log, "email")

	if err := s.SendLoginCode(context.Background(), "a@b.test", "424242"); err != nil {
		t.Fatalf("SendLoginCode: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "code=424242") {
		t.Fatalf("log missing code attribute: %q", out)
	}
	if !strings.Contains(out, "channel=email") || !strings.Contains(out, "dest=a@b.test") {
		t.Fatalf("log missing channel/dest: %q", out)
	}
}
