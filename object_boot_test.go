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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type bootFixture struct {
	gate   *ObjectBootGate
	key    ed25519.PrivateKey
	exec   ed25519.PrivateKey
	config ObjectBootstrap
	raw    []byte
	calls  atomic.Int32
	driver *bootDriver
}

type bootDriver struct {
	recordingDriver
	lifetime context.Context
	clean    atomic.Bool
}

func (d *bootDriver) Close(ctx context.Context) error {
	d.clean.Store(ctx.Err() == nil && d.lifetime.Err() == nil)
	return nil
}

func (d *bootDriver) exportSession(ctx context.Context) ([]byte, error) {
	if ctx.Err() != nil || d.lifetime.Err() != nil {
		return nil, ErrUncertain
	}
	return nil, nil
}

func (d *bootDriver) restoreSession(context.Context, []byte) error { return nil }

func newBootFixture(t *testing.T, ctx context.Context) *bootFixture {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	execPub, execKey, _ := ed25519.GenerateKey(rand.Reader)
	root := filepath.Join(t.TempDir(), "worker")
	g, err := NewObjectBootGate(ctx, pub, root, "unused")
	if err != nil {
		t.Fatal(err)
	}
	f := &bootFixture{gate: g, key: key, exec: execKey, config: ObjectBootstrap{Browser: testBootstrap(t, "alice"), Storage: syntheticS3Config()}, driver: &bootDriver{}}
	f.config.Browser.ExecutePublicKey = base64.StdEncoding.EncodeToString(execPub)
	f.raw, _ = json.Marshal(f.config)
	g.create = func(_ context.Context, c ObjectBootstrap) (*Worker, error) {
		f.calls.Add(1)
		w, err := NewBrowserWorker(c.Browser, root, "unused")
		if err == nil {
			w.CreateDriver = func(ctx context.Context) (Driver, error) { f.driver.lifetime = ctx; return f.driver, nil }
		}
		return w, err
	}
	t.Cleanup(func() {
		closing, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		g.Close(closing)
	})
	return f
}

func bootStatus(t *testing.T, g *ObjectBootGate) ObjectBootStatus {
	t.Helper()
	r := httptest.NewRecorder()
	g.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/v1/bootstrap", nil))
	var status ObjectBootStatus
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &status) != nil {
		t.Fatal("status unavailable", r.Code)
	}
	return status
}

func bootPost(g *ObjectBootGate, ctx context.Context, token string, raw []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/bootstrap", bytes.NewReader(raw)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	g.ServeHTTP(out, r)
	return out
}

func bootToken(t *testing.T, f *bootFixture) string {
	t.Helper()
	token, err := SignObjectBootstrap(f.key, bootStatus(t, f.gate).Nonce, f.raw, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func awaitBoot(t *testing.T, g *ObjectBootGate) {
	t.Helper()
	select {
	case <-g.done:
	case <-time.After(3 * time.Second):
		t.Fatal("initialization did not finish")
	}
}

func drainPost(g *ObjectBootGate, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/drain", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	g.ServeHTTP(out, r)
	return out
}

func readyBootFixture(t *testing.T) *bootFixture {
	f := newBootFixture(t, context.Background())
	if bootPost(f.gate, context.Background(), bootToken(t, f), f.raw).Code != 202 {
		t.Fatal("boot denied")
	}
	awaitBoot(t, f.gate)
	if bootStatus(t, f.gate).State != "ready" {
		t.Fatal("not ready")
	}
	return f
}

func TestObjectDrainRequiresDistinctAuthorityPurposeAndExactBoot(t *testing.T) {
	f := readyBootFixture(t)
	for _, mode := range []string{"unsigned", "execute-key", "bootstrap-token", "other-boot", "other-body", "expired", "future"} {
		status, key, expiry := bootStatus(t, f.gate), f.key, time.Now().Add(time.Minute)
		switch mode {
		case "execute-key":
			key = f.exec
		case "other-boot":
			status.Nonce = strings.Repeat("A", 43)
		case "other-body":
			status.Digest = strings.Repeat("b", 64)
		case "expired":
			expiry = time.Now().Add(-time.Minute)
		case "future":
			expiry = time.Now().Add(3 * time.Minute)
		}
		token, err := SignObjectDrain(key, status, expiry)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "unsigned" {
			token = ""
		}
		if mode == "bootstrap-token" {
			token = bootToken(t, f)
		}
		if drainPost(f.gate, token).Code != 403 || bootStatus(t, f.gate).State != "ready" {
			t.Fatal("unauthorized drain", mode)
		}
	}
	token, _ := SignObjectDrain(f.key, bootStatus(t, f.gate), time.Now().Add(time.Minute))
	if bootPost(f.gate, context.Background(), token, f.raw).Code != 403 {
		t.Fatal("drain authority accepted as bootstrap")
	}
}

func TestObjectDrainClosesOnceAndRejectsNewWorkWhileCheckpointing(t *testing.T) {
	f := readyBootFixture(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	var checkpoints atomic.Int32
	f.gate.worker.checkpoint = func(ctx context.Context, _ []byte) error {
		checkpoints.Add(1)
		if !f.driver.clean.Load() || f.driver.lifetime.Err() != nil {
			return ErrUncertain
		}
		close(entered)
		select {
		case <-finish:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	token, _ := SignObjectDrain(f.key, bootStatus(t, f.gate), time.Now().Add(time.Minute))
	if drainPost(f.gate, token).Code != 202 {
		t.Fatal("drain not accepted")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("checkpoint never began")
	}
	if status := bootStatus(t, f.gate); status.State != "stopping" {
		t.Fatal("early stop claim")
	}
	if drainPost(f.gate, token).Code != 409 {
		t.Fatal("duplicate drain accepted")
	}
	out := httptest.NewRecorder()
	f.gate.ServeHTTP(out, httptest.NewRequest("POST", "/v1/exec", nil))
	if out.Code != 503 {
		t.Fatal("new work admitted while draining")
	}
	close(finish)
	if err := f.gate.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bootStatus(t, f.gate).State != "stopped" || checkpoints.Load() != 1 || !f.driver.clean.Load() {
		t.Fatal("checkpoint did not finish exactly once")
	}
	if err := f.gate.Close(context.Background()); err != nil || checkpoints.Load() != 1 {
		t.Fatal("process shutdown repeated checkpoint")
	}
}

func TestObjectDrainFailedCheckpointNeverReportsReusable(t *testing.T) {
	f := readyBootFixture(t)
	f.gate.worker.checkpoint = func(context.Context, []byte) error { return errors.New("synthetic-private-storage-detail") }
	token, _ := SignObjectDrain(f.key, bootStatus(t, f.gate), time.Now().Add(time.Minute))
	if drainPost(f.gate, token).Code != 202 {
		t.Fatal("drain denied")
	}
	if err := f.gate.Close(context.Background()); err == nil {
		t.Fatal("checkpoint failure hidden")
	}
	status := bootStatus(t, f.gate)
	if status.State != "failed" || status.Failure != "profile-checkpoint" {
		t.Fatal("failed checkpoint reported reusable or leaked error")
	}
	if drainPost(f.gate, token).Code != 409 {
		t.Fatal("failed drain retried")
	}
}

func TestObjectBootRejectsWrongAuthorityBeforeStorage(t *testing.T) {
	for _, name := range []string{"unsigned", "execution-key", "wrong-nonce", "expired", "future", "changed-body", "oversized", "agent-credential", "issuer-execute-key", "issuer-secrets-key", "unknown-config", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newBootFixture(t, context.Background())
			raw := append([]byte(nil), f.raw...)
			key, nonce, expiry := f.key, bootStatus(t, f.gate).Nonce, time.Now().Add(time.Minute)
			ctx := context.Background()
			switch name {
			case "execution-key":
				key = f.exec
			case "wrong-nonce":
				nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			case "expired":
				expiry = time.Now().Add(-time.Minute)
			case "future":
				expiry = time.Now().Add(3 * time.Minute)
			case "agent-credential":
				f.config.Browser.InferenceKey = "synthetic-inference-secret"
				raw, _ = json.Marshal(f.config)
			case "issuer-execute-key":
				f.config.Browser.ExecutePublicKey = base64.StdEncoding.EncodeToString(f.gate.issuer)
				raw, _ = json.Marshal(f.config)
			case "issuer-secrets-key":
				f.config.Browser.SecretsPublicKey = base64.StdEncoding.EncodeToString(f.gate.issuer)
				raw, _ = json.Marshal(f.config)
			case "unknown-config":
				raw = append(raw[:len(raw)-1], []byte(`,"endpoint":"https://attacker.invalid"}`)...)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			token, err := SignObjectBootstrap(key, nonce, raw, expiry)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unsigned":
				token = "invalid"
			case "changed-body":
				raw = append(raw, ' ')
			case "oversized":
				raw = bytes.Repeat([]byte{' '}, (64<<10)+1)
			}
			if out := bootPost(f.gate, ctx, token, raw); out.Code != 403 {
				t.Fatal("unsafe bootstrap accepted", out.Code)
			}
			if f.calls.Load() != 0 || bootStatus(t, f.gate).State != "waiting" {
				t.Fatal("denied input reached storage or consumed nonce")
			}
		})
	}
}

func TestObjectBootSingleClaimSurvivesDisconnectAndDeniesRebinding(t *testing.T) {
	f := newBootFixture(t, context.Background())
	token := bootToken(t, f)
	original := f.gate.create
	entered, proceed := make(chan struct{}), make(chan struct{})
	f.gate.create = func(ctx context.Context, c ObjectBootstrap) (*Worker, error) {
		close(entered)
		<-proceed
		return original(ctx, c)
	}
	reqCtx, disconnect := context.WithCancel(context.Background())
	if out := bootPost(f.gate, reqCtx, token, f.raw); out.Code != 202 {
		t.Fatal("valid bootstrap rejected", out.Code)
	}
	disconnect()
	<-entered
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if out := bootPost(f.gate, context.Background(), token, f.raw); out.Code != 409 && out.Code != 503 {
				t.Error("duplicate bootstrap not rejected", out.Code)
			}
		})
	}
	wg.Wait()
	if bootStatus(t, f.gate).State != "starting" {
		t.Fatal("disconnect undid reservation")
	}
	close(proceed)
	awaitBoot(t, f.gate)
	status := bootStatus(t, f.gate)
	if status.State != "ready" || status.Digest != objectBootDigest(f.raw) || f.calls.Load() != 1 {
		t.Fatal("one-use bootstrap failed")
	}
	f.config.Browser.Owner = "bob"
	raw, _ := json.Marshal(f.config)
	token, _ = SignObjectBootstrap(f.key, status.Nonce, raw, time.Now().Add(time.Minute))
	if out := bootPost(f.gate, context.Background(), token, raw); out.Code != 409 || f.calls.Load() != 1 {
		t.Fatal("worker rebound to another owner")
	}
	// The public status carries only the signed body commitment, never its data.
	encoded, _ := json.Marshal(status)
	for _, secret := range []string{f.config.Browser.StorageKey, f.config.Storage.SecretAccessKey, f.config.Storage.SessionToken, "alice", f.config.Storage.Bucket} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("bootstrap status disclosed private data")
		}
	}
	for _, owner := range []string{"bob", "alice"} {
		p := Principal{Owner: owner, Audience: f.config.Browser.Audience, ID: "boot-task", Scope: "execute", Expires: time.Now().Add(time.Minute).Unix()}
		capability, _ := SignCapability(f.exec, p)
		r := httptest.NewRequest(http.MethodPost, "/v1/exec", strings.NewReader(`{"id":"boot-task","code":"return await browser.snapshot();"}`))
		r.Header.Set("Authorization", "Bearer "+capability)
		out := httptest.NewRecorder()
		f.gate.ServeHTTP(out, r)
		want := 403
		if owner == "alice" {
			want = 200
		}
		if out.Code != want {
			t.Fatal("bootstrap lost execution owner boundary", owner, out.Code)
		}
	}
	if len(f.driver.actions) != 1 {
		t.Fatal("unexpected browser effects")
	}
	if err := f.gate.Close(context.Background()); err != nil || !f.driver.clean.Load() || f.driver.lifetime.Err() == nil {
		t.Fatal("browser lifetime cancelled before clean close", err)
	}
}

func TestObjectBootQuarantinesFailureAndCannotReplayAcrossBoots(t *testing.T) {
	f := newBootFixture(t, context.Background())
	token := bootToken(t, f)
	other := newBootFixture(t, context.Background())
	other.gate.issuer = append(ed25519.PublicKey(nil), f.gate.issuer...)
	if out := bootPost(other.gate, context.Background(), token, f.raw); out.Code != 403 || other.calls.Load() != 0 {
		t.Fatal("grant replayed on a different process")
	}
	f.gate.create = func(context.Context, ObjectBootstrap) (*Worker, error) {
		f.calls.Add(1)
		return nil, errors.New("synthetic-private-diagnostic")
	}
	if out := bootPost(f.gate, context.Background(), token, f.raw); out.Code != 202 {
		t.Fatal(out.Code)
	}
	awaitBoot(t, f.gate)
	if bootStatus(t, f.gate).State != "failed" {
		t.Fatal("failed start not quarantined")
	}
	if out := bootPost(f.gate, context.Background(), token, f.raw); out.Code != 409 || strings.Contains(out.Body.String(), "synthetic-private") || f.calls.Load() != 1 {
		t.Fatal("failed start retried or disclosed diagnostics")
	}
}

func TestObjectBootCancellationAndTimeLimit(t *testing.T) {
	for _, reason := range []string{"stop", "timeout"} {
		t.Run(reason, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			f := newBootFixture(t, ctx)
			if reason == "timeout" {
				f.gate.bootLimit = 20 * time.Millisecond
			}
			entered := make(chan struct{})
			f.gate.create = func(ctx context.Context, _ ObjectBootstrap) (*Worker, error) {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			if out := bootPost(f.gate, context.Background(), bootToken(t, f), f.raw); out.Code != 202 {
				t.Fatal(out.Code)
			}
			<-entered
			if reason == "stop" {
				stop()
			}
			awaitBoot(t, f.gate)
			f.gate.mu.Lock()
			state := f.gate.status.State
			f.gate.mu.Unlock()
			if state != "failed" {
				t.Fatal("interrupted startup became ready")
			}
		})
	}
}

func TestRealChromiumObjectBoot(t *testing.T) {
	executable := os.Getenv("SURE_BROWSER_TEST_CHROME")
	if executable == "" {
		t.Skip("set SURE_BROWSER_TEST_CHROME for one-use bootstrap and real Chromium")
	}
	store, backing, key := profileFixture(t)
	for round := range 2 {
		f := newBootFixture(t, context.Background())
		f.config.Browser.Audience = "worker"
		f.config.Browser.StorageKey = base64.StdEncoding.EncodeToString(key)
		f.raw, _ = json.Marshal(f.config)
		root := privateProfileRoot(t)
		f.gate.create = func(ctx context.Context, c ObjectBootstrap) (*Worker, error) {
			return newObjectWorker(ctx, c.Browser, root, executable, store)
		}
		before := httptest.NewRecorder()
		f.gate.ServeHTTP(before, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if before.Code != 503 {
			t.Fatal("uninitialized worker advertised ready")
		}
		if out := bootPost(f.gate, context.Background(), bootToken(t, f), f.raw); out.Code != 202 {
			t.Fatal("bootstrap rejected", out.Code)
		}
		select {
		case <-f.gate.done:
		case <-time.After(30 * time.Second):
			t.Fatal("real browser initialization did not finish")
		}
		if bootStatus(t, f.gate).State != "ready" {
			t.Fatal("real browser initialization failed", round)
		}
		p := Principal{Owner: "alice", Audience: "worker", Scope: "execute", ID: "boot-round-" + string(rune('0'+round)), Expires: time.Now().Add(time.Minute).Unix()}
		token, _ := SignCapability(f.exec, p)
		body, _ := json.Marshal(ExecuteRequest{ID: p.ID, Code: `return await browser.tabs();`})
		r := httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		f.gate.ServeHTTP(out, r)
		if out.Code != 200 {
			t.Fatal("WASM could not drive the booted browser", round, out.Code)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := f.gate.Close(ctx)
		cancel()
		if err != nil {
			t.Fatal("booted worker did not save clean checkpoint", round, err)
		}
		store = reopenProfileStore(t, backing, key)
	}
}
