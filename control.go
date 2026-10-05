package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Control authenticates the application's captured account identity. Model code
// never gets the signing keys, cloud API, fleet selector or instance address.
type Control struct {
	Audience             string
	PublicKey            ed25519.PublicKey
	WorkerKey            ed25519.PrivateKey
	Fleet                *Fleet
	AllowedOwners        map[string]bool              // immutable snapshot for this process
	CredentialPublicKeys map[string]ed25519.PublicKey // operator keys, never agent keys
	mu                   sync.Mutex
	warming              map[string]bool
	agents               map[string]*agentControlLease
	// Only same-package tests may replace verified transport.
	connect func(string, string) (*http.Client, error)
	// Infrastructure lease maintenance shares the existing idle tick. Agent
	// signals and durable agent work remain in their Temporal orchestration.
	maintain func(context.Context) error
	// Set before serving, so a controller shutdown also cancels preparation.
	lifetime context.Context
}

func (c *Control) principal(r *http.Request, scope string) (Principal, error) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return Principal{}, ErrDenied
	}
	p, e := VerifyCapability(c.PublicKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), c.Audience, scope, time.Now())
	if e != nil || !c.AllowedOwners[p.Owner] || c.Fleet == nil || len(c.WorkerKey) != ed25519.PrivateKeySize {
		return Principal{}, ErrDenied
	}
	return p, nil
}

func (c *Control) prepare(owner string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Fleet.mu.Lock()
	a := c.Fleet.assignments[owner]
	state := ""
	if a != nil {
		state = a.State
	}
	c.Fleet.mu.Unlock()
	if state == "running" {
		return "ready", nil
	}
	if state == "quarantined" || state == "stopping" {
		return "", ErrUnavailable
	}
	if c.warming[owner] {
		return "starting", nil
	}
	if c.warming == nil {
		c.warming = map[string]bool{}
	}
	if len(c.warming) >= 100 {
		return "", ErrCapacity
	}
	c.warming[owner] = true
	go func() {
		parent := c.lifetime
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, BrowserStartupTimeout+time.Minute)
		defer cancel()
		_, release, e := c.Fleet.Acquire(ctx, owner)
		if e == nil {
			release()
		}
		c.mu.Lock()
		delete(c.warming, owner)
		c.mu.Unlock()
	}()
	return "starting", nil
}

func (c *Control) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		io.WriteString(w, `{"ok":true}`)
		return
	}
	if r.URL.Path == "/v1/credential-target" && r.Method == "POST" {
		c.credentialTarget(w, r)
		return
	}
	if r.Method != "POST" || (r.URL.Path != "/v1/prepare" && r.URL.Path != "/v1/exec" && r.URL.Path != "/v1/agent") {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	scope := "execute"
	if r.URL.Path == "/v1/prepare" {
		scope = "prepare"
	}
	if r.URL.Path == "/v1/agent" {
		scope = "agent"
	}
	p, e := c.principal(r, scope)
	if e != nil {
		http.Error(w, `{"error":"denied"}`, 403)
		return
	}
	if scope == "agent" {
		c.serveAgent(w, r, p)
		return
	}
	if scope == "prepare" {
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2))
		if e != nil || len(body) > 0 {
			http.Error(w, `{"error":"invalid request"}`, 400)
			return
		}
		state, e := c.prepare(p.Owner)
		if e != nil {
			http.Error(w, `{"error":"capacity or recovery unavailable"}`, 503)
			return
		}
		if state != "ready" {
			w.WriteHeader(202)
		}
		json.NewEncoder(w).Encode(map[string]string{"state": state})
		return
	}
	var req ExecuteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxCode+2048))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF || req.ID != p.ID || len(req.Code) == 0 || len(req.Code) > MaxCode {
		http.Error(w, `{"error":"invalid request"}`, 400)
		return
	}
	// Execution never launches a VM or queues a mutation behind a cold start.
	// Clients prepare separately, then authorize the actual script afresh.
	i, release, e := c.Fleet.Lease(p.Owner)
	if e != nil {
		http.Error(w, `{"error":"browser unavailable"}`, 503)
		return
	}
	defer release()
	if i.Owner != p.Owner {
		http.Error(w, `{"error":"denied"}`, 403)
		return
	}
	connect := c.connect
	if connect == nil {
		connect = VerifiedHTTP
	}
	client, e := connect(i.Domain, i.Repository)
	if e != nil || p.Expires <= time.Now().Unix() {
		http.Error(w, `{"error":"attestation or authorization unavailable"}`, 503)
		return
	}
	defer client.CloseIdleConnections()
	p.Audience = i.Name
	token, e := SignCapability(c.WorkerKey, p)
	if e != nil {
		http.Error(w, `{"error":"denied"}`, 403)
		return
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithDeadline(r.Context(), time.Unix(p.Expires, 0))
	defer cancel()
	forward, e := http.NewRequestWithContext(ctx, "POST", "https://"+i.Domain+"/v1/exec", bytes.NewReader(body))
	if e != nil {
		http.Error(w, `{"error":"denied"}`, 403)
		return
	}
	forward.Header.Set("Authorization", "Bearer "+token)
	forward.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(forward)
	if e != nil {
		http.Error(w, `{"error":"browser outcome uncertain"}`, 409)
		return
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, MaxOutput+2049))
	if e != nil || len(data) > MaxOutput+2048 {
		http.Error(w, `{"error":"browser outcome uncertain"}`, 409)
		return
	}
	if resp.StatusCode != 200 {
		status := 503
		if resp.StatusCode == 409 {
			status = 409
		}
		http.Error(w, `{"error":"browser request unavailable or uncertain"}`, status)
		return
	}
	var result RunResult
	if json.Unmarshal(data, &result) != nil || len(result.ProgramHash) != 64 || !json.Valid(result.Value) {
		http.Error(w, `{"error":"browser outcome uncertain"}`, 409)
		return
	}
	w.Write(data)
}

func (c *Control) RunIdle(ctx context.Context, idle time.Duration) error {
	if idle < time.Minute || c.Fleet == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if c.maintain != nil {
				if e := c.maintain(ctx); e != nil && !errors.Is(e, ErrUnavailable) && !errors.Is(e, ErrUncertain) && !errors.Is(e, ErrDenied) {
					return e
				}
			}
			if _, e := c.Fleet.StopIdle(ctx, idle); e != nil && !errors.Is(e, ErrUncertain) {
				return e
			}
		}
	}
}
