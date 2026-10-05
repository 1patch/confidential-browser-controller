package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type controllerBootFixture struct {
	f     *objectControllerFixture
	gate  *ControllerBootGate
	key   ed25519.PrivateKey
	raw   []byte
	calls atomic.Int32
}

func newControllerBootFixture(t *testing.T) *controllerBootFixture {
	t.Helper()
	f := newObjectControllerFixture(t, 2)
	if err := provisionObjectController(context.Background(), f.location, f.config, f.open); err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	gate, err := NewControllerBootGate(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.location)
	b := &controllerBootFixture{f: f, gate: gate, key: key, raw: raw}
	gate.load = func(ctx context.Context, location ObjectControllerLocation) (*ObjectController, error) {
		b.calls.Add(1)
		return loadObjectController(ctx, location, f.open)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if gate.Close(ctx) != nil {
			t.Error("controller initialization/maintenance did not stop")
		}
	})
	return b
}

func controllerStatus(t *testing.T, gate *ControllerBootGate) ObjectBootStatus {
	t.Helper()
	out := httptest.NewRecorder()
	gate.ServeHTTP(out, httptest.NewRequest(http.MethodGet, controllerBootPath, nil))
	var status ObjectBootStatus
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &status) != nil || !validControllerBootStatus(status) {
		t.Fatal("invalid controller status")
	}
	return status
}

func waitControllerStatus(t *testing.T, gate *ControllerBootGate, want string) ObjectBootStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := controllerStatus(t, gate)
		if status.State == want {
			return status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("controller state did not converge")
	return ObjectBootStatus{}
}

func controllerPost(gate *ControllerBootGate, token string, raw []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, controllerBootPath, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	gate.ServeHTTP(out, r)
	return out
}

func controllerOperator(t *testing.T, b *controllerBootFixture) ControllerBootOperator {
	t.Helper()
	target := CredentialTarget{Owner: "system", Audience: b.f.location.Audience, Domain: b.f.location.Audience + ".proof.containers.tinfoil.dev", Repository: "example/controller@v1@sha256:" + strings.Repeat("a", 64)}
	return ControllerBootOperator{Target: target, Key: b.key, connect: func(domain, pin string) (*http.Client, error) {
		if domain != target.Domain || pin != target.Repository {
			t.Fatal("controller attestation binding changed")
		}
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Host != target.Domain || r.URL.Path != controllerBootPath || r.GetBody != nil {
				t.Fatal("unbound, redirected or replayable controller delivery")
			}
			out := httptest.NewRecorder()
			b.gate.ServeHTTP(out, r)
			return out.Result(), nil
		})}, nil
	}}
}

func TestControllerBootstrapAttestsBeforePrivateInputAndRequiresReservation(t *testing.T) {
	b := newControllerBootFixture(t)
	o := controllerOperator(t, b)
	probe := &bootInputProbe{}
	o.connect = func(string, string) (*http.Client, error) { return nil, ErrDenied }
	if _, err := o.DeliverRecorded(context.Background(), probe, func(ObjectBootStatus) error { return nil }); err == nil || probe.reads != 0 {
		t.Fatal("failed attestation consumed private input")
	}
	o = controllerOperator(t, b)
	if _, err := o.DeliverRecorded(context.Background(), probe, nil); err == nil || probe.reads != 0 {
		t.Fatal("missing reservation accepted")
	}
	o.Target.Owner = "alice"
	if _, err := o.DeliverRecorded(context.Background(), probe, func(ObjectBootStatus) error { return nil }); err == nil || probe.reads != 0 {
		t.Fatal("tenant target accepted controller authority")
	}
	o = controllerOperator(t, b)
	if _, err := o.DeliverRecorded(context.Background(), bytes.NewReader(b.raw), func(ObjectBootStatus) error { return ErrUnavailable }); !errors.Is(err, ErrUncertain) || b.calls.Load() != 0 || controllerStatus(t, b.gate).State != "waiting" {
		t.Fatal("failed durable reservation sent controller credentials")
	}
}

func TestControllerBootstrapLostReplyInspectsExactCommitmentWithoutReplay(t *testing.T) {
	b := newControllerBootFixture(t)
	o := controllerOperator(t, b)
	connect := o.connect
	var posts atomic.Int32
	var receipt ObjectBootStatus
	o.connect = func(domain, pin string) (*http.Client, error) {
		client, err := connect(domain, pin)
		transport := client.Transport
		client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPost {
				if receipt.Digest != objectBootDigest(b.raw) || receipt.State != "starting" {
					t.Fatal("POST preceded durable intent")
				}
				posts.Add(1)
				response, err := transport.RoundTrip(r)
				if err == nil {
					response.Body.Close()
				}
				return nil, ErrUnavailable
			}
			return transport.RoundTrip(r)
		})
		return client, err
	}
	if _, err := o.DeliverRecorded(context.Background(), bytes.NewReader(b.raw), func(status ObjectBootStatus) error { receipt = status; return nil }); !errors.Is(err, ErrUncertain) {
		t.Fatal("lost acknowledgment reported successful")
	}
	waitControllerStatus(t, b.gate, "ready")
	if status, err := o.Inspect(context.Background(), receipt); err != nil || status.State != "ready" {
		t.Fatal("exact read-only recovery failed", err)
	}
	probe := &bootInputProbe{}
	if _, err := o.DeliverRecorded(context.Background(), probe, func(ObjectBootStatus) error { return nil }); err == nil || posts.Load() != 1 || probe.reads != 0 || b.calls.Load() != 1 {
		t.Fatal("accepted bootstrap replayed")
	}
	wrong := receipt
	wrong.Digest = strings.Repeat("f", 64)
	if _, err := o.Inspect(context.Background(), wrong); err == nil {
		t.Fatal("different receipt reconciled")
	}
	b.gate.mu.Lock()
	control := b.gate.control
	b.gate.mu.Unlock()
	if len(control.Fleet.assignments) != 0 {
		t.Fatal("controller bootstrap prepared a tenant")
	}
	for _, path := range []string{"/v1/prepare", "/v1/exec", "/v1/agent", "/v1/credential-target"} {
		out := httptest.NewRecorder()
		b.gate.ServeHTTP(out, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if out.Code < 400 {
			t.Fatal("bootstrap enabled an unsigned tenant operation")
		}
	}
}

func TestControllerBootstrapRejectsForeignPurposeBodyAndExpiry(t *testing.T) {
	for _, failure := range []string{"worker-purpose", "foreign-key", "wrong-nonce", "changed-body", "expired-grant", "long-grant", "expired-storage", "unknown-field"} {
		t.Run(failure, func(t *testing.T) {
			b := newControllerBootFixture(t)
			raw := bytes.Clone(b.raw)
			nonce := controllerStatus(t, b.gate).Nonce
			key, expires := b.key, time.Now().Add(time.Minute)
			if failure == "foreign-key" {
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			}
			if failure == "wrong-nonce" {
				nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			}
			if failure == "expired-grant" {
				expires = time.Now().Add(-time.Second)
			}
			if failure == "long-grant" {
				expires = time.Now().Add(3 * time.Minute)
			}
			if failure == "expired-storage" {
				location := b.f.location
				location.Storage.Expires = time.Now().Add(-time.Second).Unix()
				raw, _ = json.Marshal(location)
			}
			if failure == "unknown-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"foreign":true}`)...)
			}
			token, _ := SignControllerBootstrap(key, nonce, raw, expires)
			if failure == "worker-purpose" {
				token, _ = SignObjectBootstrap(key, nonce, raw, expires)
			}
			if failure == "changed-body" {
				raw = append(raw, ' ')
			}
			if out := controllerPost(b.gate, token, raw); out.Code != 403 || b.calls.Load() != 0 || controllerStatus(t, b.gate).State != "waiting" {
				t.Fatal("invalid bootstrap consumed controller authority", out.Code)
			}
		})
	}
}

func TestControllerBootstrapConcurrentDeliveryClaimsOnce(t *testing.T) {
	b := newControllerBootFixture(t)
	nonce := controllerStatus(t, b.gate).Nonce
	token, _ := SignControllerBootstrap(b.key, nonce, b.raw, time.Now().Add(time.Minute))
	var accepted atomic.Int32
	var done sync.WaitGroup
	for range 12 {
		done.Add(1)
		go func() {
			defer done.Done()
			if controllerPost(b.gate, token, b.raw).Code == 202 {
				accepted.Add(1)
			}
		}()
	}
	done.Wait()
	waitControllerStatus(t, b.gate, "ready")
	if accepted.Load() != 1 || b.calls.Load() != 1 {
		t.Fatal("controller initialized more than once")
	}
}

type controllerStartingProvider struct {
	testProvider
	entered chan struct{}
	stopped chan struct{}
}

func (p *controllerStartingProvider) Start(ctx context.Context, _ Instance) error {
	close(p.entered)
	<-ctx.Done()
	close(p.stopped)
	return ctx.Err()
}

func TestControllerBootstrapShutdownCancelsPreparationAndQuarantinesItsLease(t *testing.T) {
	b := newControllerBootFixture(t)
	operator := controllerOperator(t, b)
	if _, err := operator.DeliverRecorded(context.Background(), bytes.NewReader(b.raw), func(ObjectBootStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitControllerStatus(t, b.gate, "ready")
	b.gate.mu.Lock()
	control := b.gate.control
	b.gate.mu.Unlock()
	p := &controllerStartingProvider{entered: make(chan struct{}), stopped: make(chan struct{})}
	control.Fleet.provider = p
	if _, err := control.prepare("owner-0"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("preparation did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if b.gate.Close(ctx) != nil {
		t.Fatal("controller did not close")
	}
	select {
	case <-p.stopped:
	case <-ctx.Done():
		t.Fatal("preparation outlived controller")
	}
	for {
		control.mu.Lock()
		pending := len(control.warming)
		control.mu.Unlock()
		if pending == 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("preparation cleanup stalled")
		}
		time.Sleep(time.Millisecond)
	}
	control.Fleet.mu.Lock()
	state := control.Fleet.assignments["owner-0"].State
	control.Fleet.mu.Unlock()
	if state != "quarantined" {
		t.Fatal("canceled startup was reusable")
	}
}

func TestControllerRootGrantCannotBootstrapWorker(t *testing.T) {
	f := newBootFixture(t, context.Background())
	f.gate.mu.Lock()
	nonce := f.gate.status.Nonce
	f.gate.mu.Unlock()
	token, err := SignControllerBootstrap(f.key, nonce, f.raw, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/bootstrap", bytes.NewReader(f.raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	f.gate.ServeHTTP(out, r)
	if out.Code != 403 || f.calls.Load() != 0 {
		t.Fatal("controller grant accepted by worker")
	}
}

func TestControllerBootstrapFailureRetainsClaimAndHidesPrivateError(t *testing.T) {
	for _, failure := range []string{"storage", "timeout", "application-key", "worker-key", "issuer-key", "credential-key"} {
		t.Run(failure, func(t *testing.T) {
			b := newControllerBootFixture(t)
			load := b.gate.load
			b.gate.load = func(ctx context.Context, location ObjectControllerLocation) (*ObjectController, error) {
				if failure == "storage" {
					return nil, errors.New("synthetic-private-authority")
				}
				if failure == "timeout" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				c, err := load(ctx, location)
				if err != nil {
					return nil, err
				}
				root := b.key.Public().(ed25519.PublicKey)
				switch failure {
				case "application-key":
					c.Control.PublicKey = root
				case "worker-key":
					c.Control.WorkerKey = b.key
				case "issuer-key":
					c.provisioner.key = b.key
				case "credential-key":
					c.Control.CredentialPublicKeys["owner-0"] = root
				}
				return c, nil
			}
			if failure == "timeout" {
				b.gate.bootLimit = 10 * time.Millisecond
			}
			token, _ := SignControllerBootstrap(b.key, controllerStatus(t, b.gate).Nonce, b.raw, time.Now().Add(time.Minute))
			if out := controllerPost(b.gate, token, b.raw); out.Code != 202 {
				t.Fatal("claim failed")
			}
			status := waitControllerStatus(t, b.gate, "failed")
			if status.Digest != objectBootDigest(b.raw) || status.Failure != "" {
				t.Fatal("failed startup exposed secrets or lost commitment")
			}
			if out := controllerPost(b.gate, token, b.raw); out.Code != 409 {
				t.Fatal("failed bootstrap allowed retry")
			}
			out := httptest.NewRecorder()
			b.gate.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if out.Code != 503 {
				t.Fatal("failed controller became ready")
			}
		})
	}
}
