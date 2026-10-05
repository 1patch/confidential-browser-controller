package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testBlob struct {
	data    []byte
	version string
}
type testBlobBackend struct {
	mu              sync.Mutex
	objects         map[string]testBlob
	writes          int
	failAt          int
	commitFailed    bool
	cancelAt        int
	cancel          context.CancelFunc
	barrierKey      string
	barrierReads    int
	barrier         chan struct{}
	barrierExisting bool
}

func newTestBlobs() *testBlobBackend { return &testBlobBackend{objects: map[string]testBlob{}} }
func (b *testBlobBackend) Get(ctx context.Context, key string) ([]byte, string, error) {
	b.mu.Lock()
	v, ok := b.objects[key]
	var gate chan struct{}
	if key == b.barrierKey && (!ok || b.barrierExisting) && b.barrierReads < 2 {
		gate = b.barrier
		b.barrierReads++
		if b.barrierReads == 2 {
			close(gate)
		}
	}
	b.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	if !ok {
		return nil, "", os.ErrNotExist
	}
	return bytes.Clone(v.data), v.version, nil
}
func (b *testBlobBackend) Put(ctx context.Context, key string, data []byte, version string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	b.writes++
	previous, exists := b.objects[key]
	if exists && version != previous.version || !exists && version != "" {
		return "", ErrUncertain
	}
	next := fmt.Sprintf(`"v%d"`, b.writes)
	if b.writes != b.failAt || b.commitFailed {
		b.objects[key] = testBlob{bytes.Clone(data), next}
	}
	if b.writes == b.cancelAt {
		b.cancel()
	}
	if b.writes == b.failAt {
		return "", ErrUnavailable
	}
	return next, nil
}

func testRemoteStore(t *testing.T) (*SealedStore, *testBlobBackend, []byte) {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	backing := newTestBlobs()
	s, err := newRemoteSealedStore(context.Background(), "alice", "worker", key, backing, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, backing, key
}

func TestRemoteStoreEncryptsAndBindsIdentity(t *testing.T) {
	s, backing, key := testRemoteStore(t)
	ctx := context.Background()
	secret := []byte("synthetic-browser-secret")
	if err := s.PutContext(ctx, "alice", "credential", "vault", secret); err != nil {
		t.Fatal(err)
	}
	for _, blob := range backing.objects {
		if bytes.Contains(blob.data, secret) {
			t.Fatal("plaintext left the store")
		}
	}
	reopened, err := newRemoteSealedStore(ctx, "alice", "worker", key, backing, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetContext(ctx, "alice", "credential", "vault")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("remote restart lost data", err)
	}
	if _, err = reopened.GetContext(ctx, "bob", "credential", "vault"); err == nil {
		t.Fatal("foreign owner read")
	}
	if err = reopened.PutContext(ctx, "bob", "credential", "vault", secret); err == nil {
		t.Fatal("foreign owner write")
	}
	for _, changed := range []struct {
		owner, audience string
		key             []byte
	}{{"bob", "worker", key}, {"alice", "other-worker", key}, {"alice", "worker", make([]byte, 32)}} {
		if _, err = newRemoteSealedStore(ctx, changed.owner, changed.audience, changed.key, backing, true); err == nil {
			t.Fatal("existing identity was replaced")
		}
	}
	if _, err = newRemoteSealedStore(ctx, "alice", "worker", key, newTestBlobs(), false); err == nil {
		t.Fatal("worker initialized missing remote state")
	}
	_, source, _, _ := s.binding("alice", "credential", "vault")
	_, other, _, _ := s.binding("alice", "execution", "request")
	backing.objects[filepath.Base(other)] = backing.objects[filepath.Base(source)]
	if _, err = reopened.GetContext(ctx, "alice", "execution", "request"); err == nil {
		t.Fatal("ciphertext substituted across purpose")
	}
	if err = reopened.PutContext(ctx, "alice", "credential", "vault", secret); !errors.Is(err, ErrUncertain) {
		t.Fatal("tampered store continued writes")
	}
}

type atomicDriver struct{ actions atomic.Int32 }

func (*atomicDriver) CurrentURL(context.Context, string) (string, error) {
	return "https://example.com", nil
}
func (d *atomicDriver) Do(context.Context, Action) (Observation, error) {
	d.actions.Add(1)
	return Observation{Text: "synthetic"}, nil
}
func (*atomicDriver) Close(context.Context) error { return nil }
func remoteWorker(s *SealedStore, d *atomicDriver) *Worker {
	return &Worker{Owner: "alice", Audience: "worker", Store: s, driver: d, Sandbox: Sandbox{Safety: StubSafety{}}, CreateDriver: func(context.Context) (Driver, error) { return d, nil }}
}
func remoteRequest() (Principal, ExecuteRequest) {
	return Principal{Owner: "alice", Audience: "worker", Scope: "execute", ID: "request", Expires: time.Now().Add(time.Minute).Unix()}, ExecuteRequest{ID: "request", Code: `return await browser.snapshot();`}
}

func TestRemoteJournalCompetingWorkersRunOnce(t *testing.T) {
	s, backing, key := testRemoteStore(t)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	other, err := newRemoteSealedStore(ctx, "alice", "worker", key, backing, false)
	if err != nil {
		t.Fatal(err)
	}
	_, path, _, _ := s.binding("alice", "execution", "request")
	backing.barrierKey, backing.barrier = filepath.Base(path), make(chan struct{})
	d := &atomicDriver{}
	p, request := remoteRequest()
	results := make(chan error, 2)
	for _, store := range []*SealedStore{s, other} {
		go func() { _, err := remoteWorker(store, d).Execute(ctx, p, request); results <- err }()
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) || d.actions.Load() != 1 {
		t.Fatal("competing reservations executed more than once", a, b, d.actions.Load())
	}
	recovered, err := newRemoteSealedStore(ctx, "alice", "worker", key, backing, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remoteWorker(recovered, d).Execute(ctx, p, request); err != nil || d.actions.Load() != 1 {
		t.Fatal("recovery replayed completed effects", err)
	}
}

func TestRemoteJournalLostAcknowledgementsNeverReplay(t *testing.T) {
	for _, stage := range []struct {
		name      string
		write     int
		commit    bool
		actions   int32
		recovered bool
	}{
		{"pending-saved", 2, true, 0, false}, {"pending-not-saved", 2, false, 0, true},
		{"complete-saved", 3, true, 1, true}, {"complete-not-saved", 3, false, 1, false},
	} {
		t.Run(stage.name, func(t *testing.T) {
			s, backing, key := testRemoteStore(t)
			backing.failAt, backing.commitFailed = stage.write, stage.commit
			d := &atomicDriver{}
			p, request := remoteRequest()
			if _, err := remoteWorker(s, d).Execute(context.Background(), p, request); err == nil || d.actions.Load() != stage.actions {
				t.Fatal("ambiguous persistence accepted", err, d.actions.Load())
			}
			if err := s.Put("alice", "execution", "other", []byte("test")); !errors.Is(err, ErrUncertain) {
				t.Fatal("ambiguous writer continued")
			}
			backing.failAt = 0
			reopened, err := newRemoteSealedStore(context.Background(), "alice", "worker", key, backing, false)
			if err != nil {
				t.Fatal(err)
			}
			if stage.name == "pending-not-saved" {
				// No action started and no marker exists. This test performs explicit
				// recovery; the failed request path itself never retries anything.
				_, err = reopened.Get("alice", "execution", "request")
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unexpected pending record")
				}
				return
			}
			_, err = remoteWorker(reopened, d).Execute(context.Background(), p, request)
			if (err == nil) != stage.recovered || d.actions.Load() != stage.actions {
				t.Fatal("recovery repeated an uncertain action", err, d.actions.Load())
			}
		})
	}
}

func TestRemoteJournalCancellationAfterReservationHasNoEffects(t *testing.T) {
	s, backing, _ := testRemoteStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing.cancelAt, backing.cancel = 2, cancel
	d := &atomicDriver{}
	p, request := remoteRequest()
	if _, err := remoteWorker(s, d).Execute(ctx, p, request); err == nil || d.actions.Load() != 0 {
		t.Fatal("cancelled authority reached the browser", err)
	}
}
