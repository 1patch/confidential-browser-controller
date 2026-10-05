package browser

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type executionRecord struct {
	Hash   string     `json:"hash"`
	State  string     `json:"state"`
	Result *RunResult `json:"result,omitempty"`
}

// Worker is bound to one owner for its entire lifetime. An instance must never
// be recycled to another owner, even after idle shutdown or a failed provision.
type Worker struct {
	Owner            string
	Audience         string
	PublicKey        ed25519.PublicKey
	SecretsPublicKey ed25519.PublicKey
	CredentialPolicy NetworkPolicy
	Store            *SealedStore
	Sandbox          Sandbox
	CreateDriver     func(context.Context) (Driver, error)
	Agent            AgentEndpoint
	mu               sync.Mutex
	driver           Driver
	closed           bool
	closeErr         error
	checkpoint       func(context.Context, []byte) error
	restoreSession   []byte
	shutdownTimeout  time.Duration
}

func (w *Worker) initializeLocked(ctx context.Context) error {
	if w.closed || w.CreateDriver == nil || w.Store == nil {
		return ErrUnavailable
	}
	if w.driver != nil {
		return nil
	}
	secrets, e := w.credentials(ctx)
	if e != nil {
		return startupFailure("credentials-read", e)
	}
	w.driver, e = w.CreateDriver(ctx)
	if e != nil {
		return startupFailure("chromium-launch", e)
	}
	if len(w.restoreSession) > 0 {
		restorer, ok := w.driver.(privateBrowserSession)
		if !ok || restorer.restoreSession(ctx, w.restoreSession) != nil {
			w.driver.Close(ctx)
			w.driver = nil
			clear(w.restoreSession)
			w.restoreSession = nil
			w.closed, w.closeErr = true, ErrUncertain
			return startupFailure("session-restore", ErrUnavailable)
		}
		clear(w.restoreSession)
		w.restoreSession = nil
	}
	for _, secret := range secrets {
		installer, ok := w.driver.(credentialInstaller)
		if !ok || installer.InstallCredential(ctx, secret) != nil {
			w.driver.Close(ctx)
			w.driver = nil
			return startupFailure("credential-install", ErrUnavailable)
		}
	}
	return nil
}

// Initialize uses the service lifetime context, before readiness is advertised.
func (w *Worker) Initialize(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.initializeLocked(ctx)
}

func (w *Worker) Execute(ctx context.Context, p Principal, req ExecuteRequest) (RunResult, error) {
	var zero RunResult
	if p.Owner != w.Owner || p.Audience != w.Audience || p.Scope != "execute" || p.ID != req.ID || p.Expires <= time.Now().Unix() || !identifier.MatchString(req.ID) || len(req.Code) == 0 || len(req.Code) > MaxCode || w.Store == nil || w.CreateDriver == nil {
		return zero, ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(p.Expires, 0))
	defer cancel()
	// Serialize browser state, credential changes and the durable no-replay marker.
	w.mu.Lock()
	defer func() {
		w.Store.releaseRead(w.Owner, "execution", req.ID)
		w.mu.Unlock()
	}()
	if ctx.Err() != nil || p.Expires <= time.Now().Unix() || w.closed {
		return zero, ErrDenied
	}
	digest := sha256.Sum256([]byte(req.Code))
	hash := hex.EncodeToString(digest[:])
	saved, err := w.Store.GetContext(ctx, w.Owner, "execution", req.ID)
	if err == nil {
		var record executionRecord
		if json.Unmarshal(saved, &record) != nil || record.Hash != hash {
			return zero, ErrDenied
		}
		if record.State == "complete" && record.Result != nil {
			return *record.Result, nil
		}
		return zero, ErrUncertain
	}
	if !errors.Is(err, os.ErrNotExist) {
		return zero, ErrUnavailable
	}
	if w.driver == nil {
		if err = w.initializeLocked(context.Background()); err != nil {
			return zero, err
		}
	}
	marker, _ := json.Marshal(executionRecord{Hash: hash, State: "in-progress"})
	if w.Store.CreateContext(ctx, w.Owner, "execution", req.ID, marker) != nil {
		return zero, ErrUnavailable
	}
	// Expiring a capability also cancels an execution already in progress.
	if ctx.Err() != nil {
		return zero, ErrUncertain
	}
	result, err := w.Sandbox.Execute(ctx, w.Owner, req.Code, w.driver)
	if err != nil {
		return zero, ErrUncertain
	} // Effects may have preceded the failure.
	finished, _ := json.Marshal(executionRecord{Hash: hash, State: "complete", Result: &result})
	if w.Store.PutContext(ctx, w.Owner, "execution", req.ID, finished) != nil {
		return zero, ErrUncertain
	}
	return result, nil
}

func (w *Worker) Close(ctx context.Context) error {
	if w.Agent != nil {
		w.Agent.Close()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	if w.driver != nil {
		var session []byte
		if w.checkpoint != nil {
			if source, ok := w.driver.(privateBrowserSession); ok {
				session, w.closeErr = source.exportSession(ctx)
			} else {
				w.closeErr = ErrUnavailable
			}
		}
		defer clear(session)
		closeErr := w.driver.Close(ctx)
		if w.closeErr == nil {
			w.closeErr = closeErr
		}
		if w.closeErr == nil && w.checkpoint != nil {
			w.closeErr = w.checkpoint(ctx, session)
		}
	} else if w.checkpoint != nil {
		w.closeErr = ErrUncertain
	}
	return w.closeErr
}

func (w *Worker) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		w.mu.Lock()
		ready := w.driver != nil && !w.closed
		w.mu.Unlock()
		if !ready {
			http.Error(out, `{"error":"not ready"}`, 503)
			return
		}
		io.WriteString(out, `{"ok":true}`)
		return
	}
	if r.URL.Path == "/v1/credentials" && r.Method == "POST" {
		p, err := VerifyCapability(w.SecretsPublicKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), w.Audience, "credential.write", time.Now())
		if err != nil || p.Owner != w.Owner {
			http.Error(out, `{"error":"denied"}`, 403)
			return
		}
		var secret CookieCredential
		dec := json.NewDecoder(http.MaxBytesReader(out, r.Body, 12<<10))
		dec.DisallowUnknownFields()
		if dec.Decode(&secret) != nil || dec.Decode(new(any)) != io.EOF {
			http.Error(out, `{"error":"invalid request"}`, 400)
			return
		}
		if w.putCredential(r.Context(), p, secret) != nil {
			http.Error(out, `{"error":"credential unavailable"}`, 503)
			return
		}
		io.WriteString(out, `{"stored":true}`)
		return
	}
	if r.URL.Path == "/v1/agent" && r.Method == "POST" {
		p, err := VerifyCapability(w.PublicKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), w.Audience, "agent", time.Now())
		if err != nil || p.Owner != w.Owner || w.Agent == nil {
			http.Error(out, `{"error":"denied"}`, 403)
			return
		}
		var step AgentStep
		dec := json.NewDecoder(http.MaxBytesReader(out, r.Body, MaxAgentMessage))
		dec.DisallowUnknownFields()
		if dec.Decode(&step) != nil || dec.Decode(new(any)) != io.EOF {
			http.Error(out, `{"error":"invalid request"}`, 400)
			return
		}
		result, err := w.Agent.Step(r.Context(), p, step)
		if err != nil {
			http.Error(out, `{"error":"agent outcome unavailable or uncertain"}`, 409)
			return
		}
		json.NewEncoder(out).Encode(result)
		return
	}
	if r.URL.Path != "/v1/exec" || r.Method != "POST" {
		http.Error(out, `{"error":"not found"}`, 404)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(out, `{"error":"denied"}`, 403)
		return
	}
	p, err := VerifyCapability(w.PublicKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), w.Audience, "execute", time.Now())
	if err != nil || p.Owner != w.Owner {
		http.Error(out, `{"error":"denied"}`, 403)
		return
	}
	var req ExecuteRequest
	dec := json.NewDecoder(http.MaxBytesReader(out, r.Body, MaxCode+2048))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF {
		http.Error(out, `{"error":"invalid request"}`, 400)
		return
	}
	result, err := w.Execute(r.Context(), p, req)
	if err != nil {
		status := 503
		if errors.Is(err, ErrDenied) {
			status = 403
		}
		if errors.Is(err, ErrUncertain) {
			status = 409
		}
		out.WriteHeader(status)
		json.NewEncoder(out).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(out).Encode(result)
}
