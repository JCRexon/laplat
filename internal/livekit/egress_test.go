package livekit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// StartRoomComposite posts the right Twirp path, a bearer token, a room-composite
// body, and parses the EgressInfo response.
func TestEgress_StartRoomComposite(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"egressId":"EG_1","roomName":"ses_x","status":"EGRESS_STARTING"}`))
	}))
	defer srv.Close()

	c, err := NewEgressClient(srv.URL, "api-key", "secret", "/rec/")
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.StartRoomComposite(context.Background(), "ses_x")
	if err != nil {
		t.Fatalf("StartRoomComposite: %v", err)
	}

	if gotPath != "/twirp/livekit.Egress/StartRoomCompositeEgress" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") || len(gotAuth) < len("Bearer ")+10 {
		t.Fatalf("auth = %q, want a bearer token", gotAuth)
	}
	if gotBody["room_name"] != "ses_x" {
		t.Fatalf("room_name = %v", gotBody["room_name"])
	}
	outs, ok := gotBody["file_outputs"].([]any)
	if !ok || len(outs) != 1 {
		t.Fatalf("file_outputs = %v", gotBody["file_outputs"])
	}
	fp, _ := outs[0].(map[string]any)["filepath"].(string)
	if !strings.HasPrefix(fp, "/rec/ses_x-") {
		t.Fatalf("filepath = %q, want the /rec/ prefix", fp)
	}
	if info.EgressID != "EG_1" || info.Status != EgressStarting {
		t.Fatalf("info = %+v", info)
	}
}

// StopEgress posts the egress id and surfaces the returned status + output.
func TestEgress_StopEgress(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		if !strings.HasSuffix(r.URL.Path, "/StopEgress") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"egressId":"EG_1","status":"EGRESS_COMPLETE","file":{"location":"s3://b/ses_x.mp4"}}`))
	}))
	defer srv.Close()

	c, _ := NewEgressClient(srv.URL, "k", "s", "")
	info, err := c.StopEgress(context.Background(), "EG_1")
	if err != nil {
		t.Fatalf("StopEgress: %v", err)
	}
	if gotBody["egress_id"] != "EG_1" {
		t.Fatalf("egress_id = %v", gotBody["egress_id"])
	}
	if info.Status != EgressComplete || info.Output() != "s3://b/ses_x.mp4" {
		t.Fatalf("info = %+v, output = %q", info, info.Output())
	}
}

// A non-200 from the egress API is surfaced as an error, not a zero EgressInfo.
func TestEgress_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"permission_denied"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	c, _ := NewEgressClient(srv.URL, "k", "s", "")
	if _, err := c.StartRoomComposite(context.Background(), "ses_x"); err == nil {
		t.Fatal("expected an error on a 403 response")
	}
}

func TestNewEgressClient_Validation(t *testing.T) {
	if _, err := NewEgressClient("", "k", "s", ""); err == nil {
		t.Fatal("empty base url should error")
	}
	if _, err := NewEgressClient("http://x", "", "", ""); err == nil {
		t.Fatal("missing credentials should error")
	}
	c, err := NewEgressClient("http://x/", "k", "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.filePrefix != "/out/" {
		t.Fatalf("default file prefix = %q, want /out/", c.filePrefix)
	}
}
