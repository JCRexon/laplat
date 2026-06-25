package livekit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Egress status values LiveKit reports on an EgressInfo. Mapped to our own
// recording statuses by the recording service.
const (
	EgressStarting     = "EGRESS_STARTING"
	EgressActive       = "EGRESS_ACTIVE"
	EgressEnding       = "EGRESS_ENDING"
	EgressComplete     = "EGRESS_COMPLETE"
	EgressFailed       = "EGRESS_FAILED"
	EgressAborted      = "EGRESS_ABORTED"
	EgressLimitReached = "EGRESS_LIMIT_REACHED"
)

// EgressInfo is the subset of LiveKit's EgressInfo we consume.
type EgressInfo struct {
	EgressID string `json:"egressId"`
	RoomName string `json:"roomName"`
	Status   string `json:"status"`
	Error    string `json:"error"`
	// File is the most recent file result, when egress has produced one.
	File     *EgressFile   `json:"file"`
	FileList []*EgressFile `json:"fileResults"`
}

// EgressFile is a produced recording file.
type EgressFile struct {
	Filename string `json:"filename"`
	Location string `json:"location"`
}

// Output returns the best-known output location for the recording, or "".
func (e *EgressInfo) Output() string {
	if e.File != nil {
		if e.File.Location != "" {
			return e.File.Location
		}
		return e.File.Filename
	}
	for _, f := range e.FileList {
		if f.Location != "" {
			return f.Location
		}
		if f.Filename != "" {
			return f.Filename
		}
	}
	return ""
}

// EgressClient calls the LiveKit server's Egress (Twirp/JSON) API to start and
// stop room recordings. Stdlib-only, matching the Granter ethos; auth is an
// HS256 JWT carrying a roomRecord grant, signed with the project API secret.
type EgressClient struct {
	baseURL    string // http(s) base of the LiveKit server, no trailing slash
	apiKey     string
	apiSecret  []byte
	filePrefix string // path/prefix file outputs are written under (e.g. "/out/")
	http       *http.Client
	ttl        time.Duration
	Now        func() time.Time
}

// NewEgressClient validates config and builds the client. baseURL is the
// LiveKit server's HTTP(S) endpoint; filePrefix is where file outputs land.
func NewEgressClient(baseURL, apiKey, apiSecret, filePrefix string) (*EgressClient, error) {
	if baseURL == "" {
		return nil, errors.New("livekit: egress base url is required")
	}
	if apiKey == "" || apiSecret == "" {
		return nil, errors.New("livekit: api key and secret are required")
	}
	if filePrefix == "" {
		filePrefix = "/out/"
	}
	return &EgressClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		apiSecret:  []byte(apiSecret),
		filePrefix: strings.TrimRight(filePrefix, "/") + "/",
		http:       &http.Client{Timeout: 15 * time.Second},
		ttl:        10 * time.Minute,
		Now:        time.Now,
	}, nil
}

// StartRoomComposite starts a room-composite egress recording the whole room to
// a single MP4 file. The filepath embeds the room name and LiveKit's {time}
// template so concurrent/sequential recordings never collide.
func (c *EgressClient) StartRoomComposite(ctx context.Context, room string) (*EgressInfo, error) {
	if room == "" {
		return nil, errors.New("livekit: room is required")
	}
	req := map[string]any{
		"room_name": room,
		"layout":    "grid",
		"file_outputs": []map[string]any{{
			"file_type": "MP4",
			"filepath":  c.filePrefix + room + "-{time}.mp4",
		}},
	}
	return c.call(ctx, "StartRoomCompositeEgress", req)
}

// StopEgress stops an in-flight egress by id.
func (c *EgressClient) StopEgress(ctx context.Context, egressID string) (*EgressInfo, error) {
	if egressID == "" {
		return nil, errors.New("livekit: egress id is required")
	}
	return c.call(ctx, "StopEgress", map[string]any{"egress_id": egressID})
}

func (c *EgressClient) call(ctx context.Context, method string, body any) (*EgressInfo, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := c.baseURL + "/twirp/livekit.Egress/" + method
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.authToken())

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("livekit: egress %s: %s: %s", method, resp.Status, strings.TrimSpace(string(respBody)))
	}
	var info EgressInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("livekit: decoding egress response: %w", err)
	}
	return &info, nil
}

// authToken mints the short-lived HS256 JWT the Egress API requires, carrying a
// roomRecord grant (the service-level permission egress needs).
func (c *EgressClient) authToken() string {
	now := c.now()
	claims := map[string]any{
		"iss":   c.apiKey,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(c.ttl).Unix(),
		"video": map[string]any{"roomRecord": true},
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, c.apiSecret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil))
}

func (c *EgressClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
