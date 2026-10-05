package browser

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *SealedStore {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, e := NewSealedStore(dir, key)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

type testProvider struct {
	mu                                  sync.Mutex
	created, started, stopped, verified int
	failCreate, failStop, failVerify    bool
}

func (p *testProvider) Create(_ context.Context, owner, name string) (Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.created++
	if p.failCreate {
		return Instance{}, ErrUncertain
	}
	return Instance{Owner: owner, ID: name, Name: name, Domain: name + ".example.test", Repository: "test/config@v1@sha256:synthetic"}, nil
}
func (p *testProvider) Start(context.Context, Instance) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started++
	return nil
}
func (p *testProvider) Stop(context.Context, Instance) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped++
	if p.failStop {
		return ErrUncertain
	}
	return nil
}
func (p *testProvider) Verify(context.Context, Instance) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verified++
	if p.failVerify {
		return ErrDenied
	}
	return nil
}

func TestFleet100ConcurrentOwnersAndIdleWake(t *testing.T) {
	p := &testProvider{}
	store := testStore(t)
	f, e := NewFleet(store, p, 100)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	releases := []func(){}
	ids := map[string]bool{}
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			instance, release, err := f.Acquire(context.Background(), fmt.Sprintf("owner-%d", i))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Error(err)
				return
			}
			if ids[instance.ID] {
				t.Error("instance shared across owners")
			}
			ids[instance.ID] = true
			releases = append(releases, release)
		}()
	}
	wg.Wait()
	if len(ids) != 100 || p.created != 100 || p.verified != 100 {
		t.Fatal("capacity not reached", len(ids), p.created, p.verified)
	}
	if _, _, err := f.Acquire(context.Background(), "owner-101"); err != ErrCapacity {
		t.Fatal("cap exceeded", err)
	}
	now := time.Now().Add(10 * time.Minute)
	f.clock = func() time.Time { return now }
	if count, err := f.StopIdle(context.Background(), time.Minute); err != nil || count != 0 {
		t.Fatal("active leases stopped", count, err)
	}
	for _, release := range releases {
		release()
		release()
	}
	now = now.Add(10 * time.Minute)
	if count, err := f.StopIdle(context.Background(), time.Minute); err != nil || count != 100 {
		t.Fatal("idle shutdown", count, err)
	}
	f2, e := NewFleet(store, p, 100)
	if e != nil {
		t.Fatal(e)
	}
	instance, release, e := f2.Acquire(context.Background(), "owner-0")
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if !ids[instance.ID] || p.created != 100 || p.started != 101 {
		t.Fatal("wake changed ownership")
	}
}

type blockingStopProvider struct {
	testProvider
	entered         chan Instance
	permit          chan struct{}
	active, maximum int
}

func (p *blockingStopProvider) Stop(ctx context.Context, i Instance) error {
	p.mu.Lock()
	p.active++
	p.maximum = max(p.maximum, p.active)
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active--; p.mu.Unlock() }()
	p.entered <- i
	select {
	case <-ctx.Done():
		return ErrUncertain
	case <-p.permit:
		if i.Owner == "owner-0" {
			return ErrUncertain
		}
		return nil
	}
}

func TestFleetIdleStopsOverlapButRetainUnconfirmedCapacity(t *testing.T) {
	p := &blockingStopProvider{entered: make(chan Instance, 100), permit: make(chan struct{})}
	store := testStore(t)
	f, _ := NewFleet(store, p, 100)
	for i := range 100 {
		_, release, err := f.Acquire(context.Background(), fmt.Sprintf("owner-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	now := time.Now().Add(10 * time.Minute)
	f.clock = func() time.Time { return now }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		stopped int
		err     error
	}
	done := make(chan result, 1)
	go func() { n, err := f.StopIdle(ctx, time.Minute); done <- result{n, err} }()
	// Eight cloud operations enter before any stop completes. A sequential
	// implementation cannot pass this rendezvous; no timing sleep is needed.
	for range 8 {
		select {
		case <-p.entered:
		case <-ctx.Done():
			t.Fatal("idle shutdown serialized")
		}
	}
	if _, _, err := f.Acquire(ctx, "owner-101"); err != ErrCapacity {
		t.Fatal("unconfirmed capacity released", err)
	}
	if n, err := f.StopIdle(ctx, time.Minute); err != nil || n != 0 {
		t.Fatal("stopping workers stopped twice", n, err)
	}
	close(p.permit)
	r := <-done
	if r.stopped != 99 || r.err != ErrUncertain || p.maximum != 8 {
		t.Fatal("shutdown bound or uncertainty lost", r, p.maximum)
	}
	recovered, err := NewFleet(store, p, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recovered.Acquire(ctx, "owner-0"); err != ErrUnavailable {
		t.Fatal("uncertain shutdown reused after restart", err)
	}
	_, release, err := recovered.Acquire(ctx, "owner-1")
	if err != nil {
		t.Fatal("confirmed worker did not wake", err)
	}
	release()
}

func TestFleetQuarantinesAmbiguousCreateAndCrash(t *testing.T) {
	p := &testProvider{failCreate: true}
	store := testStore(t)
	f, _ := NewFleet(store, p, 100)
	for range 3 {
		if _, _, e := f.Acquire(context.Background(), "alice"); e == nil {
			t.Fatal("ambiguous creation accepted")
		}
	}
	if p.created != 1 {
		t.Fatal("ambiguous create replayed")
	}
	p.failCreate = false
	f2, _ := NewFleet(store, p, 100)
	if _, _, e := f2.Acquire(context.Background(), "alice"); e == nil || p.created != 1 {
		t.Fatal("restart lost quarantine")
	}
	_, release, e := f2.Acquire(context.Background(), "bob")
	if e != nil {
		t.Fatal(e)
	}
	release()
	f3, _ := NewFleet(store, p, 100)
	if _, _, e = f3.Acquire(context.Background(), "bob"); e == nil {
		t.Fatal("crash silently reused running instance")
	}
}

func TestWorkerAuthorizationReplayAndVaultIsolation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secretPub, secretPriv, _ := ed25519.GenerateKey(rand.Reader)
	d := &recordingDriver{}
	w := &Worker{Owner: "alice", Audience: "one", PublicKey: pub, SecretsPublicKey: secretPub, Store: testStore(t), Sandbox: Sandbox{Safety: StubSafety{}}, CreateDriver: func(context.Context) (Driver, error) { return d, nil }, CredentialPolicy: NetworkPolicy{[]string{"https://example.com"}}}
	call := func(owner, scope, path, body string, key ed25519.PrivateKey) *httptest.ResponseRecorder {
		t.Helper()
		token, _ := SignCapability(key, Principal{Owner: owner, Audience: "one", Scope: scope, ID: "req-1", Expires: time.Now().Add(time.Minute).Unix()})
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		w.ServeHTTP(out, req)
		return out
	}
	body := `{"id":"req-1","code":"return browser.snapshot();"}`
	if r := call("bob", "execute", "/v1/exec", body, priv); r.Code != 403 || len(d.actions) != 0 {
		t.Fatal("cross-owner", r.Code)
	}
	if r := call("alice", "execute", "/v1/exec", body, priv); r.Code != 200 {
		t.Fatal("execution", r.Code, r.Body.String())
	}
	if r := call("alice", "execute", "/v1/exec", body, priv); r.Code != 200 || len(d.actions) != 1 {
		t.Fatal("duplicate effect", r.Code, len(d.actions))
	}
	if r := call("alice", "execute", "/v1/exec", `{"id":"req-1","code":"return 2;"}`, priv); r.Code != 403 {
		t.Fatal("id substitution", r.Code)
	}
	if r := call("alice", "execute", "/v1/exec", `{"owner":"bob","id":"req-2","code":"return 2;"}`, priv); r.Code != 400 {
		t.Fatal("model owner override", r.Code)
	}
	secret := `{"name":"login","origin":"https://example.com","cookieName":"__Host-session","value":"sentinel"}`
	if r := call("alice", "credential.write", "/v1/credentials", secret, priv); r.Code != 403 {
		t.Fatal("agent signing key accessed vault", r.Code)
	}
	w.driver = nil
	if r := call("alice", "credential.write", "/v1/credentials", secret, secretPriv); r.Code != 200 || strings.Contains(r.Body.String(), "sentinel") {
		t.Fatal("vault write", r.Code)
	}
	if r := call("alice", "execute", "/v1/credentials/get", `{}`, priv); r.Code != 404 {
		t.Fatal("vault read route")
	}
	data, e := w.Store.Get("alice", "credential", "vault")
	if e != nil {
		t.Fatal(e)
	}
	var saved map[string]CookieCredential
	if json.Unmarshal(data, &saved) != nil || saved["login"].Value != "sentinel" {
		t.Fatal("trusted vault retrieval")
	}
}
