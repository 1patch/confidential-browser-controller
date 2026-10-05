package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type objectFixtureDriver struct {
	lifetime context.Context
	effects  *atomic.Int32
}

func (d *objectFixtureDriver) CurrentURL(context.Context, string) (string, error) {
	return "https://example.com", nil
}
func (d *objectFixtureDriver) Do(context.Context, Action) (Observation, error) {
	d.effects.Add(1)
	return Observation{URL: "https://example.com", Text: "synthetic-fixture"}, nil
}
func (d *objectFixtureDriver) Close(context.Context) error {
	if d.lifetime.Err() != nil {
		return ErrUncertain
	}
	return nil
}
func (d *objectFixtureDriver) exportSession(context.Context) ([]byte, error) {
	if d.lifetime.Err() != nil {
		return nil, ErrUncertain
	}
	return nil, nil
}
func (d *objectFixtureDriver) restoreSession(context.Context, []byte) error { return nil }

type objectProvisionFixture struct {
	t              *testing.T
	p              *ObjectProvisioner
	provider       *TinfoilProvider
	instances      map[string]Instance
	states         map[string]string
	gates          map[string]*ObjectBootGate
	backing        map[string]*testBlobBackend
	effects        map[string]*atomic.Int32
	exec           map[string]ed25519.PrivateKey
	control        *testBlobBackend
	controlKey     []byte
	mu             sync.Mutex
	posts          atomic.Int32
	deploys        atomic.Int32
	lostAck        bool
	lostDrainAck   bool
	lostRenewalAck bool
	dropRenewal    bool
	renewals       atomic.Int32
	drains         atomic.Int32
	crash          bool
	reuseNonce     bool
}

func newObjectProvisionFixture(t *testing.T, count int) *objectProvisionFixture {
	t.Helper()
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	rand.Read(key)
	f := &objectProvisionFixture{t: t, instances: map[string]Instance{}, states: map[string]string{}, gates: map[string]*ObjectBootGate{}, backing: map[string]*testBlobBackend{}, effects: map[string]*atomic.Int32{}, exec: map[string]ed25519.PrivateKey{}, control: newTestBlobs(), controlKey: key}
	store, err := newRemoteSealedStore(context.Background(), "system", "controller", key, f.control, true)
	if err != nil {
		t.Fatal(err)
	}
	f.provider = &TinfoilProvider{AdminKey: "admin_synthetic", Repository: "example/browser@v1@sha256:" + strings.Repeat("a", 64), DomainSuffix: "proof.containers.tinfoil.dev"}
	owners := map[string]ObjectOwnerPolicy{}
	for index := range count {
		owner := fmt.Sprintf("owner-%d", index)
		name := fmt.Sprintf("browser-%024x", index+1)
		i := Instance{Owner: owner, Name: name, ID: fmt.Sprintf("00000000-0000-0000-0000-%012x", index+1), Domain: name + "." + f.provider.DomainSuffix, Repository: f.provider.Repository}
		f.instances[owner], f.states[i.ID], f.backing[owner], f.effects[owner] = i, "stopped", newTestBlobs(), &atomic.Int32{}
		pub, private, _ := ed25519.GenerateKey(rand.Reader)
		base := testBootstrap(t, owner)
		base.Audience, base.StorageKey, base.ExecutePublicKey = "", "", base64.StdEncoding.EncodeToString(pub)
		storage := syntheticS3Config()
		storage.Bucket = "browser-proof-" + owner
		storage.AccessKeyID += owner
		owners[owner], f.exec[owner] = ObjectOwnerPolicy{Browser: base, Storage: storage}, private
	}
	f.p, err = NewObjectProvisioner(f.provider, store, issuer, owners)
	if err != nil {
		t.Fatal(err)
	}
	f.provider.Provisioner = f.p
	f.p.open = func(ctx context.Context, c ObjectBootstrap, create bool) (*SealedStore, error) {
		backing := f.backing[c.Browser.Owner]
		if backing == nil || c.Storage.Bucket != f.p.owners[c.Browser.Owner].Storage.Bucket {
			return nil, ErrDenied
		}
		key, _ := base64.StdEncoding.DecodeString(c.Browser.StorageKey)
		defer clear(key)
		return newRemoteSealedStore(ctx, c.Browser.Owner, c.Browser.Audience, key, backing, create)
	}
	f.provider.client = &http.Client{Transport: roundTripFunc(f.cloud)}
	f.p.connect = func(domain, pin string) (*http.Client, error) {
		if pin != f.provider.Repository {
			return nil, ErrDenied
		}
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Host != domain {
				return nil, ErrDenied
			}
			f.mu.Lock()
			gate := f.gates[domain]
			f.mu.Unlock()
			if gate == nil {
				return nil, ErrUnavailable
			}
			out := httptest.NewRecorder()
			if r.Method == "POST" && r.URL.Path == "/v1/storage" {
				f.renewals.Add(1)
				if f.dropRenewal {
					return nil, ErrUnavailable
				}
			}
			gate.ServeHTTP(out, r)
			if r.Method == "POST" && r.URL.Path == "/v1/storage" && f.lostRenewalAck {
				return nil, ErrUnavailable
			}
			if r.Method == "POST" && r.URL.Path == "/v1/bootstrap" {
				f.posts.Add(1)
				if f.lostAck {
					return nil, ErrUnavailable
				}
			}
			if r.Method == "POST" && r.URL.Path == "/v1/drain" {
				f.drains.Add(1)
				if f.lostDrainAck {
					return nil, ErrUnavailable
				}
			}
			return out.Result(), nil
		})}, nil
	}
	f.provider.connect = f.p.connect
	return f
}

func (f *objectProvisionFixture) cloud(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "api.tinfoil.sh" || r.Header.Get("Authorization") != "Bearer admin_synthetic" {
		return nil, ErrDenied
	}
	var instance Instance
	for _, i := range f.instances {
		if strings.HasPrefix(r.URL.Path, "/api/containers/"+i.ID) {
			instance = i
			break
		}
	}
	if instance.ID == "" {
		return nil, ErrDenied
	}
	f.mu.Lock()
	state, gate := f.states[instance.ID], f.gates[instance.Domain]
	f.mu.Unlock()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/containers/" + instance.ID:
		body, _ := json.Marshal(containerStatus{ID: instance.ID, Name: instance.Name, Domain: instance.Domain, Repo: "example/browser", Tag: "v1", Status: state, CPUs: 2, Memory: 8192})
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	case "POST /api/containers/" + instance.ID + "/deploy":
		f.deploys.Add(1)
		oldNonce := ""
		if gate != nil {
			oldNonce = bootStatus(f.t, gate).Nonce
		}
		gate, err := NewObjectBootGate(context.Background(), f.p.key.Public().(ed25519.PublicKey), privateProfileRoot(f.t), "unused")
		if err != nil {
			return nil, err
		}
		if f.reuseNonce && oldNonce != "" {
			gate.status.Nonce = oldNonce
		}
		root := privateProfileRoot(f.t)
		gate.create = func(ctx context.Context, c ObjectBootstrap) (*Worker, error) {
			store, err := f.p.open(ctx, c, false)
			if err != nil {
				return nil, err
			}
			w, err := newObjectWorker(ctx, c.Browser, root, "unused", store)
			if err == nil {
				w.CreateDriver = func(lifetime context.Context) (Driver, error) {
					return &objectFixtureDriver{lifetime: lifetime, effects: f.effects[instance.Owner]}, nil
				}
			}
			return w, err
		}
		f.t.Cleanup(func() { gate.Close(context.Background()) })
		f.mu.Lock()
		f.gates[instance.Domain], f.states[instance.ID] = gate, "running"
		f.mu.Unlock()
	case "POST /api/containers/" + instance.ID + "/stop":
		if gate != nil {
			// Actual cloud power-off cannot be assumed to run application cleanup.
			// Persistence must have completed over the attested drain first.
			gate.cancel()
		}
		f.mu.Lock()
		f.states[instance.ID] = "stopped"
		f.mu.Unlock()
	default:
		return nil, ErrDenied
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

func (f *objectProvisionFixture) execute(owner, id string) int {
	i := f.instances[owner]
	p := Principal{Owner: owner, Audience: i.Name, Scope: "execute", ID: id, Expires: time.Now().Add(time.Minute).Unix()}
	token, _ := SignCapability(f.exec[owner], p)
	body, _ := json.Marshal(ExecuteRequest{ID: id, Code: `return await browser.snapshot();`})
	r := httptest.NewRequest("POST", "https://"+i.Domain+"/v1/exec", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	f.mu.Lock()
	gate := f.gates[i.Domain]
	f.mu.Unlock()
	out := httptest.NewRecorder()
	gate.ServeHTTP(out, r)
	return out.Code
}

func TestObjectProvisionerStopWakePreservesIdentityAndNeverReplaysEffects(t *testing.T) {
	f := newObjectProvisionFixture(t, 1)
	i := f.instances["owner-0"]
	var storageKey string
	for round := range 2 {
		if err := f.provider.Start(context.Background(), i); err != nil {
			t.Fatal("start", round, err)
		}
		if err := f.provider.Verify(context.Background(), i); err != nil {
			t.Fatal("verify", round, err)
		}
		r, err := f.p.load(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		if round == 0 {
			storageKey = r.Bootstrap.Browser.StorageKey
		} else if storageKey != r.Bootstrap.Browser.StorageKey {
			t.Fatal("wake replaced storage identity")
		}
		if status := f.execute(i.Owner, "retained-operation"); status != 200 {
			t.Fatal("execute", status)
		}
		if err := f.provider.Stop(context.Background(), i); err != nil {
			t.Fatal("stop", round, err)
		}
	}
	if f.effects[i.Owner].Load() != 1 || f.posts.Load() != 2 || f.deploys.Load() != 2 || f.drains.Load() != 2 {
		t.Fatal("replayed effects or bootstrap")
	}
}

func TestObjectProvisionerLostBootAckResolvesWithoutAnotherPost(t *testing.T) {
	f := newObjectProvisionFixture(t, 1)
	f.lostAck = true
	i := f.instances["owner-0"]
	if err := f.provider.Start(context.Background(), i); err != nil {
		t.Fatal("lost acknowledgment was not resolved read-only", err)
	}
	if err := f.provider.Start(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if f.posts.Load() != 1 || f.deploys.Load() != 1 {
		t.Fatal("uncertain POST was replayed")
	}
}

func TestObjectProvisionerLostDrainAckIsInspectedBeforePowerOff(t *testing.T) {
	f := newObjectProvisionFixture(t, 1)
	i := f.instances["owner-0"]
	if err := f.provider.Start(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	f.lostDrainAck = true
	if err := f.provider.Stop(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if f.drains.Load() != 1 || f.states[i.ID] != "stopped" {
		t.Fatal("lost drain was replayed or power-off failed")
	}
	if err := f.provider.Start(context.Background(), i); err != nil {
		t.Fatal("checkpoint did not survive forced cloud stop", err)
	}
}

func TestObjectProvisionerUnconfirmedDrainReservationCannotPowerOffOrResend(t *testing.T) {
	f := newObjectProvisionFixture(t, 1)
	i := f.instances["owner-0"]
	if err := f.provider.Start(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	f.control.mu.Lock()
	f.control.failAt, f.control.commitFailed = f.control.writes+1, true
	f.control.mu.Unlock()
	if err := f.provider.Stop(context.Background(), i); err == nil {
		t.Fatal("unconfirmed drain reservation allowed stop")
	}
	if f.drains.Load() != 0 || f.states[i.ID] != "running" {
		t.Fatal("unreserved drain or power-off occurred")
	}
	store, err := newRemoteSealedStore(context.Background(), "system", "controller", f.controlKey, f.control, false)
	if err != nil {
		t.Fatal(err)
	}
	f.p.store = store
	if err := f.provider.Stop(context.Background(), i); err == nil || f.drains.Load() != 0 || f.states[i.ID] != "running" {
		t.Fatal("uncertain intent was resent after reopen")
	}
}

func TestObjectProvisionerUncleanStopAndRepeatedNonceCannotWake(t *testing.T) {
	for _, reason := range []string{"unclean", "reused-nonce"} {
		t.Run(reason, func(t *testing.T) {
			f := newObjectProvisionFixture(t, 1)
			i := f.instances["owner-0"]
			if err := f.provider.Start(context.Background(), i); err != nil {
				t.Fatal(err)
			}
			f.crash = reason == "unclean"
			if f.crash {
				f.gates[i.Domain].cancel()
				f.states[i.ID] = "stopped"
			}
			err := f.provider.Stop(context.Background(), i)
			if f.crash && err == nil {
				t.Fatal("unclean stop marked reusable")
			}
			if !f.crash && err != nil {
				t.Fatal(err)
			}
			f.reuseNonce = reason == "reused-nonce"
			if err := f.provider.Start(context.Background(), i); err == nil {
				t.Fatal("unsafe worker woke")
			}
			if f.posts.Load() != 1 {
				t.Fatal("unsafe wake received another private bootstrap")
			}
		})
	}
}

func TestObjectProvisionerDurableBootReservationPrecedesSecretDelivery(t *testing.T) {
	f := newObjectProvisionFixture(t, 1)
	i := f.instances["owner-0"]
	if err := f.p.Prepare(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	f.control.mu.Lock()
	f.control.failAt = f.control.writes + 1
	f.control.commitFailed = true
	f.control.mu.Unlock()
	if err := f.provider.Start(context.Background(), i); err == nil {
		t.Fatal("failed durable reservation accepted")
	}
	if f.posts.Load() != 0 {
		t.Fatal("private bootstrap sent before confirmed reservation")
	}
	// Reopening a committed-but-unacknowledged reservation must still inspect
	// its original nonce, never turn it back into a new POST opportunity.
	store, err := newRemoteSealedStore(context.Background(), "system", "controller", f.controlKey, f.control, false)
	if err != nil {
		t.Fatal(err)
	}
	f.p.store = store
	if err := f.provider.Start(context.Background(), i); err == nil || f.posts.Load() != 0 {
		t.Fatal("reopened uncertain reservation resent secrets")
	}
}

func TestObjectProvisionerRejectsChangedOwnersPoliciesAndSharedCloudCredentials(t *testing.T) {
	f := newObjectProvisionFixture(t, 2)
	i := f.instances["owner-0"]
	if err := f.p.Prepare(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	changed := i
	changed.Owner = "owner-1"
	if err := f.p.Prepare(context.Background(), changed); err == nil {
		t.Fatal("another owner reused provisioning record")
	}
	owners := map[string]ObjectOwnerPolicy{}
	for owner, c := range f.p.owners {
		owners[owner] = c
	}
	bob := owners["owner-1"]
	bob.Storage = owners["owner-0"].Storage
	owners["owner-1"] = bob
	if _, err := NewObjectProvisioner(f.provider, f.p.store, f.p.key, owners); err == nil {
		t.Fatal("shared bucket or credential accepted")
	}
	raw, err := f.p.store.Get("system", "object-provision", i.Name)
	if err != nil {
		t.Fatal(err)
	}
	var r objectProvisionRecord
	json.Unmarshal(raw, &r)
	r.Bootstrap.Browser.Origins = []string{"https://attacker.invalid"}
	raw, _ = json.Marshal(r)
	if err = f.p.store.Put("system", "object-provision", i.Name, raw); err != nil {
		t.Fatal(err)
	}
	if err = f.p.Prepare(context.Background(), i); err == nil {
		t.Fatal("stored policy disagreed with operator enrollment")
	}
}

func TestObjectProvisionerIndependentOwnersDoNotSerializeColdStarts(t *testing.T) {
	f := newObjectProvisionFixture(t, 2)
	open := f.p.open
	entered, proceed := make(chan struct{}), make(chan struct{})
	f.p.open = func(ctx context.Context, c ObjectBootstrap, create bool) (*SealedStore, error) {
		if create && c.Browser.Owner == "owner-0" {
			close(entered)
			select {
			case <-proceed:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return open(ctx, c, create)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- f.provider.Start(ctx, f.instances["owner-0"]) }()
	<-entered
	go func() { second <- f.provider.Start(ctx, f.instances["owner-1"]) }()
	var secondErr error
	blocked := false
	select {
	case secondErr = <-second:
	case <-time.After(2 * time.Second):
		blocked = true
	}
	close(proceed)
	firstErr := <-first
	if blocked {
		secondErr = <-second
	}
	if blocked || firstErr != nil || secondErr != nil || f.posts.Load() != 2 {
		t.Fatal("one owner's cold start blocked another", firstErr, secondErr)
	}
}

func TestObjectProvisionerKeepsObservedCASVersionUntilBootstrapReservation(t *testing.T) {
	f := newObjectProvisionFixture(t, 1)
	i := f.instances["owner-0"]
	other, err := newRemoteSealedStore(context.Background(), "system", "controller", f.controlKey, f.control, false)
	if err != nil {
		t.Fatal(err)
	}
	connect := f.p.connect
	var once sync.Once
	f.p.connect = func(domain, pin string) (*http.Client, error) {
		once.Do(func() {
			raw, err := other.Get("system", "object-provision", i.Name)
			if err != nil {
				t.Fatal(err)
			}
			if err = other.Put("system", "object-provision", i.Name, raw); err != nil {
				t.Fatal(err)
			}
			clear(raw)
		})
		return connect(domain, pin)
	}
	if err = f.provider.Start(context.Background(), i); err == nil || f.posts.Load() != 0 {
		t.Fatal("stale reservation overwrote a competing controller or sent secrets")
	}
}
