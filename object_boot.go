package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ObjectBootStatus is deliberately public. No owner, storage configuration,
// credentials or underlying initialization error is returned by this endpoint.
type ObjectBootStatus struct {
	Version           int    `json:"version"`
	Nonce             string `json:"nonce"`
	State             string `json:"state"`
	Digest            string `json:"digest,omitempty"`
	Failure           string `json:"failure,omitempty"`
	StorageGeneration uint64 `json:"storageGeneration,omitempty"`
	StorageDigest     string `json:"storageDigest,omitempty"`
	StorageState      string `json:"storageState,omitempty"`
	StorageExpires    int64  `json:"storageExpires,omitempty"`
}

type objectBootGrant struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Digest  string `json:"digest"`
	Expires int64  `json:"expires"`
}

func objectBootDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// SignObjectBootstrap is an operator operation. A separate key signs the exact
// private body for a freshly attested process nonce; execution grants cannot boot
// a worker. The client must retain the target, nonce and digest on uncertainty.
func SignObjectBootstrap(key ed25519.PrivateKey, nonce string, raw []byte, expires time.Time) (string, error) {
	n, err := base64.RawURLEncoding.DecodeString(nonce)
	if len(key) != ed25519.PrivateKeySize || err != nil || len(n) != 32 || base64.RawURLEncoding.EncodeToString(n) != nonce || len(raw) == 0 || len(raw) > 64<<10 {
		return "", ErrInvalid
	}
	body, _ := json.Marshal(objectBootGrant{1, nonce, objectBootDigest(raw), expires.Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(key, []byte("browser-bootstrap/v1."+encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyObjectBootGrant(key ed25519.PublicKey, token, nonce string, now time.Time) (objectBootGrant, error) {
	return verifyObjectGrant(key, token, nonce, now, "browser-bootstrap/v1.")
}

// SignObjectDrain belongs to the bootstrap operator, never the agent. It binds
// checkpoint authority to the exact process and bootstrap already delivered.
func SignObjectDrain(key ed25519.PrivateKey, status ObjectBootStatus, expires time.Time) (string, error) {
	nonce, err := base64.RawURLEncoding.DecodeString(status.Nonce)
	if len(key) != ed25519.PrivateKeySize || status.Version != 1 || err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != status.Nonce || !hexIdentifier(status.Digest, 32) {
		return "", ErrInvalid
	}
	body, _ := json.Marshal(objectBootGrant{1, status.Nonce, status.Digest, expires.Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(key, []byte("browser-drain/v1."+encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyObjectGrant(key ed25519.PublicKey, token, nonce string, now time.Time, purpose string) (objectBootGrant, error) {
	var grant objectBootGrant
	parts := strings.Split(token, ".")
	if len(key) != ed25519.PublicKeySize || len(token) > 2048 || len(parts) != 2 {
		return grant, ErrDenied
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(key, []byte(purpose+parts[0]), sig) {
		return grant, ErrDenied
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return grant, ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&grant) != nil || d.Decode(new(any)) != io.EOF || grant.Version != 1 || grant.Nonce != nonce || grant.Expires <= now.Unix() || grant.Expires > now.Add(2*time.Minute).Unix() {
		return objectBootGrant{}, ErrDenied
	}
	hash, err := hex.DecodeString(grant.Digest)
	if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != grant.Digest {
		return objectBootGrant{}, ErrDenied
	}
	return grant, nil
}

// ObjectBootGate accepts exactly one bootstrap in a process lifetime. It must
// sit behind the attested enclave TLS shim. The issuer public key is inline in
// measured configuration, never a mutable provider variable. Failed starts stay
// quarantined: no new nonce, reset route, owner replacement or implicit retry.
type ObjectBootGate struct {
	ctx           context.Context
	issuer        ed25519.PublicKey
	mu            sync.Mutex
	closeMu       sync.Mutex
	status        ObjectBootStatus
	worker        *Worker
	lifetime      context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	reading       chan struct{}
	create        func(context.Context, ObjectBootstrap) (*Worker, error)
	bootLimit     time.Duration
	drainClaimed  bool
	closeFinished bool
	closeErr      error
	storageTimer  *time.Timer
	renew         func(context.Context, *Worker, S3StoreConfig) error
}

func NewObjectBootGate(ctx context.Context, issuer ed25519.PublicKey, root, executable string) (*ObjectBootGate, error) {
	if ctx == nil || ctx.Err() != nil || len(issuer) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	lifetime, cancel := context.WithCancel(context.Background())
	g := &ObjectBootGate{ctx: ctx, issuer: append(ed25519.PublicKey(nil), issuer...), lifetime: lifetime, cancel: cancel,
		status: ObjectBootStatus{Version: 1, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), State: "waiting"},
		done:   make(chan struct{}), reading: make(chan struct{}, 2), bootLimit: 90 * time.Second}
	g.create = func(ctx context.Context, c ObjectBootstrap) (*Worker, error) {
		return NewObjectWorker(ctx, c, root, executable)
	}
	g.renew = func(ctx context.Context, w *Worker, c S3StoreConfig) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.closed || ctx.Err() != nil || w.Store == nil {
			return ErrDenied
		}
		return w.Store.renewS3Credentials(ctx, w.Owner, w.Audience, c, nil)
	}
	return g, nil
}

func (g *ObjectBootGate) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("Content-Type", "application/json")
	deny := func() { http.Error(out, `{"error":"denied"}`, http.StatusForbidden) }
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || g.ctx.Err() != nil {
		deny()
		return
	}
	g.mu.Lock()
	status, worker := g.status, g.worker
	g.mu.Unlock()
	if r.URL.Path == "/v1/drain" {
		g.drain(out, r, status)
		return
	}
	if r.URL.Path == "/v1/storage" {
		g.renewStorage(out, r, status)
		return
	}
	if r.URL.Path != "/v1/bootstrap" {
		if status.State != "ready" || worker == nil {
			http.Error(out, `{"error":"not ready"}`, http.StatusServiceUnavailable)
			return
		}
		worker.ServeHTTP(out, r)
		return
	}
	if r.Method == http.MethodGet {
		json.NewEncoder(out).Encode(status)
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		deny()
		return
	}
	grant, err := verifyObjectBootGrant(g.issuer, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), status.Nonce, time.Now())
	if err != nil {
		deny()
		return
	}
	select {
	case g.reading <- struct{}{}:
		defer func() { <-g.reading }()
	default:
		http.Error(out, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(out, r.Body, 64<<10))
	defer clear(raw)
	if err != nil || grant.Digest != objectBootDigest(raw) {
		deny()
		return
	}
	c, err := ParseObjectBootstrap(raw)
	issuer := base64.StdEncoding.EncodeToString(g.issuer)
	if err != nil || c.Browser.ExecutePublicKey == issuer || c.Browser.SecretsPublicKey == issuer || !storageLeaseUsable(c.Storage, time.Now()) {
		deny()
		return
	}
	g.mu.Lock()
	if g.status.State != "waiting" {
		g.mu.Unlock()
		http.Error(out, `{"error":"bootstrap already claimed"}`, http.StatusConflict)
		return
	}
	if r.Context().Err() != nil || g.ctx.Err() != nil || grant.Expires <= time.Now().Unix() {
		g.mu.Unlock()
		deny()
		return
	}
	g.status.State, g.status.Digest = "starting", grant.Digest
	g.status.StorageExpires = c.Storage.Expires
	status = g.status
	g.mu.Unlock()
	// After the claim, disconnecting cannot undo initialization or make another
	// POST safe. Status lets the operator resolve a lost acknowledgment read-only.
	go g.initialize(c)
	out.WriteHeader(http.StatusAccepted)
	json.NewEncoder(out).Encode(status)
}

// Claim before starting asynchronous shutdown. A lost acknowledgment is resolved
// only through GET /v1/bootstrap; no second request can start another checkpoint.
func (g *ObjectBootGate) drain(out http.ResponseWriter, r *http.Request, status ObjectBootStatus) {
	deny := func() { http.Error(out, `{"error":"denied"}`, http.StatusForbidden) }
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		deny()
		return
	}
	grant, err := verifyObjectGrant(g.issuer, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), status.Nonce, time.Now(), "browser-drain/v1.")
	if err != nil || grant.Digest != status.Digest {
		deny()
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(out, r.Body, 1))
	if err != nil || len(body) != 0 || r.Context().Err() != nil {
		deny()
		return
	}
	g.mu.Lock()
	if g.status.State != "ready" || g.drainClaimed || g.ctx.Err() != nil || grant.Expires <= time.Now().Unix() {
		g.mu.Unlock()
		http.Error(out, `{"error":"drain unavailable or claimed"}`, http.StatusConflict)
		return
	}
	g.drainClaimed = true
	g.status.State = "stopping"
	status = g.status
	g.mu.Unlock()
	go func() {
		// Up to 90 seconds for an already admitted grant, then the existing
		// 90-second checkpoint budget. New requests are already denied.
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		_ = g.Close(ctx)
	}()
	out.WriteHeader(http.StatusAccepted)
	json.NewEncoder(out).Encode(status)
}

func (g *ObjectBootGate) initialize(c ObjectBootstrap) {
	defer close(g.done)
	stop := context.AfterFunc(g.ctx, g.cancel)
	timer := time.AfterFunc(g.bootLimit, g.cancel)
	worker, err := g.create(g.lifetime, c)
	c = ObjectBootstrap{}
	if err == nil && worker != nil {
		err = worker.Initialize(g.lifetime)
	}
	// A fired cancellation callback may still be waiting to run. Do not publish
	// readiness on the strength of a context whose cancellation is in flight.
	timerStopped, parentStopped := timer.Stop(), stop()
	if !timerStopped || !parentStopped {
		err = ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.worker = worker
	if err != nil || worker == nil || g.lifetime.Err() != nil || g.ctx.Err() != nil || g.status.State != "starting" {
		g.cancel()
		if g.status.State == "starting" {
			g.status.State = "failed"
			g.status.Failure = startupFailureCode(err)
		}
		return
	}
	g.status.State = "ready"
	g.scheduleStorageExpiryLocked()
}

// Close is called only after the HTTP server drains. Keep the Chromium lifetime
// alive until the encrypted profile checkpoint completes on an ordinary stop.
func (g *ObjectBootGate) Close(ctx context.Context) error {
	g.closeMu.Lock()
	defer g.closeMu.Unlock()
	if g.closeFinished {
		return g.closeErr
	}
	g.mu.Lock()
	if g.storageTimer != nil {
		g.storageTimer.Stop()
	}
	previous := g.status.State
	g.status.State = "stopping"
	g.status.Failure = ""
	if previous == "waiting" {
		close(g.done)
	}
	if previous != "ready" && !(previous == "stopping" && g.drainClaimed) {
		g.cancel()
	}
	g.mu.Unlock()
	defer g.cancel()
	select {
	case <-g.done:
	case <-ctx.Done():
		g.closeFinished, g.closeErr = true, ErrUncertain
		g.mu.Lock()
		g.status.State, g.status.Failure = "failed", "profile-checkpoint"
		g.mu.Unlock()
		return ErrUncertain
	}
	g.mu.Lock()
	worker := g.worker
	g.mu.Unlock()
	var err error
	if worker != nil {
		err = worker.Close(ctx)
	}
	g.mu.Lock()
	if err == nil {
		g.status.State = "stopped"
	} else {
		g.status.State, g.status.Failure = "failed", "profile-checkpoint"
	}
	g.mu.Unlock()
	g.closeFinished, g.closeErr = true, err
	return err
}

func ServeObjectBootGate(ctx context.Context, address string, gate *ObjectBootGate) error {
	err := Serve(ctx, address, gate)
	closing, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	closeErr := gate.Close(closing)
	if err == nil {
		err = closeErr
	}
	return err
}
