package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const controllerBootPath = "/v1/controller-bootstrap"
const controllerBootPurpose = "browser-controller-bootstrap/v1."

// ControllerBootGate exposes only a fresh nonce until an independent operator
// delivers a signed location over attested TLS. The enrollment and issuer stay
// encrypted in S3. A failed start never accepts a second location or root key.
type ControllerBootGate struct {
	ctx       context.Context
	cancel    context.CancelFunc
	issuer    ed25519.PublicKey
	mu        sync.Mutex
	status    ObjectBootStatus
	control   *Control
	done      chan struct{}
	reading   chan struct{}
	bootLimit time.Duration
	load      func(context.Context, ObjectControllerLocation) (*ObjectController, error)
}

func NewControllerBootGate(parent context.Context, issuer ed25519.PublicKey) (*ControllerBootGate, error) {
	if parent == nil || parent.Err() != nil || len(issuer) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	return &ControllerBootGate{ctx: ctx, cancel: cancel, issuer: append(ed25519.PublicKey(nil), issuer...),
		status: ObjectBootStatus{Version: 1, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), State: "waiting"},
		done:   make(chan struct{}), reading: make(chan struct{}, 2), bootLimit: 90 * time.Second, load: NewObjectController}, nil
}

func SignControllerBootstrap(key ed25519.PrivateKey, nonce string, raw []byte, expires time.Time) (string, error) {
	n, err := base64.RawURLEncoding.DecodeString(nonce)
	if len(key) != ed25519.PrivateKeySize || err != nil || len(n) != 32 || base64.RawURLEncoding.EncodeToString(n) != nonce || len(raw) == 0 || len(raw) > 32<<10 {
		return "", ErrInvalid
	}
	body, _ := json.Marshal(objectBootGrant{1, nonce, objectBootDigest(raw), expires.Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(controllerBootPurpose+encoded))), nil
}

func (g *ControllerBootGate) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("Content-Type", "application/json")
	deny := func() { http.Error(out, `{"error":"denied"}`, http.StatusForbidden) }
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || g.ctx.Err() != nil {
		deny()
		return
	}
	g.mu.Lock()
	status, control := g.status, g.control
	g.mu.Unlock()
	if r.URL.Path != controllerBootPath {
		if status.State != "ready" || control == nil {
			http.Error(out, `{"error":"not ready"}`, http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(g.ctx, cancel)
		defer stop()
		defer cancel()
		control.ServeHTTP(out, r.WithContext(ctx))
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
	grant, err := verifyObjectGrant(g.issuer, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), status.Nonce, time.Now(), controllerBootPurpose)
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
	raw, err := io.ReadAll(http.MaxBytesReader(out, r.Body, 32<<10))
	defer clear(raw)
	if err != nil || grant.Digest != objectBootDigest(raw) {
		deny()
		return
	}
	location, err := ParseObjectControllerLocation(raw)
	if err != nil || !storageLeaseUsable(location.Storage, time.Now()) {
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
	status = g.status
	g.mu.Unlock()
	go g.initialize(location)
	out.WriteHeader(http.StatusAccepted)
	json.NewEncoder(out).Encode(status)
}

func (g *ControllerBootGate) initialize(location ObjectControllerLocation) {
	defer close(g.done)
	bounded, cancel := context.WithTimeout(g.ctx, g.bootLimit)
	controller, err := g.load(bounded, location)
	location = ObjectControllerLocation{}
	if bounded.Err() != nil {
		err = ErrUnavailable
	}
	cancel()
	if err == nil {
		err = controller.independentRoot(g.issuer)
	}
	g.mu.Lock()
	if err != nil || g.ctx.Err() != nil || g.status.State != "starting" {
		g.status.State = "failed"
		g.mu.Unlock()
		return
	}
	controller.Control.lifetime = g.ctx
	g.control, g.status.State = controller.Control, "ready"
	g.mu.Unlock()
	// Infrastructure maintenance uses the existing loop. Agent work remains in
	// Temporal; a bootstrap neither prepares an owner nor starts a browser.
	_ = controller.Control.RunIdle(g.ctx, controller.idle)
	g.mu.Lock()
	g.control, g.status.State = nil, "failed"
	g.mu.Unlock()
	g.cancel()
}

func (c *ObjectController) independentRoot(root ed25519.PublicKey) error {
	if c == nil || c.Control == nil || c.provisioner == nil || c.Control.Fleet == nil || c.idle < time.Minute || c.idle > time.Hour || len(c.Control.WorkerKey) != ed25519.PrivateKeySize || len(c.provisioner.key) != ed25519.PrivateKeySize {
		return ErrDenied
	}
	for _, key := range []ed25519.PublicKey{c.Control.PublicKey, c.Control.WorkerKey.Public().(ed25519.PublicKey), c.provisioner.key.Public().(ed25519.PublicKey)} {
		if bytes.Equal(key, root) {
			return ErrDenied
		}
	}
	for _, key := range c.Control.CredentialPublicKeys {
		if bytes.Equal(key, root) {
			return ErrDenied
		}
	}
	return nil
}

func (g *ControllerBootGate) Close(ctx context.Context) error {
	g.cancel()
	g.mu.Lock()
	waiting := g.status.State == "waiting"
	g.mu.Unlock()
	if waiting {
		return nil
	}
	select {
	case <-g.done:
		return nil
	case <-ctx.Done():
		return ErrUncertain
	}
}

func ServeControllerBootGate(ctx context.Context, address string, gate *ControllerBootGate) error {
	if gate == nil {
		return ErrInvalid
	}
	err := Serve(ctx, address, gate)
	closing, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if closeErr := gate.Close(closing); err == nil {
		err = closeErr
	}
	return err
}
