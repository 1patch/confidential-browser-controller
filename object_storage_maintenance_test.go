package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type storageIssuerFunc func(context.Context, string, string) (S3StoreConfig, error)

func (f storageIssuerFunc) Issue(ctx context.Context, owner, audience string) (S3StoreConfig, error) {
	return f(ctx, owner, audience)
}

func automaticStorageFixture(t *testing.T, count int) (*objectProvisionFixture, *time.Time, *atomic.Int32) {
	t.Helper()
	f := newObjectProvisionFixture(t, count)
	now := time.Now()
	issued := &atomic.Int32{}
	f.p.clock = func() time.Time { return now }
	f.p.issuer = storageIssuerFunc(func(ctx context.Context, owner, audience string) (S3StoreConfig, error) {
		if audience != f.instances[owner].Name || ctx.Err() != nil {
			return S3StoreConfig{}, ErrDenied
		}
		storage := f.p.owners[owner].Storage
		storage.AccessKeyID += fmt.Sprint(issued.Add(1))
		storage.Expires = now.Add(time.Hour).Unix()
		return storage, nil
	})
	return f, &now, issued
}

func enableFixtureRenewal(f *objectProvisionFixture, i Instance) {
	f.gates[i.Domain].renew = func(context.Context, *Worker, S3StoreConfig) error { return nil }
}

func TestAutomaticStorageInitialIssuanceFailureCannotCreateIdentityOrBoot(t *testing.T) {
	f, _, issued := automaticStorageFixture(t, 1)
	i, ctx := f.instances["owner-0"], context.Background()
	f.p.issuer = storageIssuerFunc(func(context.Context, string, string) (S3StoreConfig, error) {
		return S3StoreConfig{}, ErrUnavailable
	})
	if err := f.provider.Start(ctx, i); err == nil {
		t.Fatal("failed initial issuance permitted boot")
	}
	if _, err := f.p.load(ctx, i); !errors.Is(err, os.ErrNotExist) || issued.Load() != 0 || f.deploys.Load() != 0 || f.posts.Load() != 0 {
		t.Fatal("failed issuance persisted preparation or contacted the worker")
	}
	if len(f.backing[i.Owner].objects) != 0 {
		t.Fatal("failed issuance created a browser identity")
	}
}

func TestAutomaticStorageFirstBootRenewalAndExpiredStoppedWake(t *testing.T) {
	f, clock, issued := automaticStorageFixture(t, 1)
	i, ctx := f.instances["owner-0"], context.Background()
	if err := f.provider.Start(ctx, i); err != nil || issued.Load() != 1 {
		t.Fatal("first boot did not issue once", err)
	}
	enableFixtureRenewal(f, i)
	original, _ := f.p.load(ctx, i)
	if original.currentStorage().AccessKeyID == f.p.owners[i.Owner].Storage.AccessKeyID || original.Storage == nil {
		t.Fatal("boot used stale enrollment credential")
	}
	if err := f.p.MaintainStorage(ctx, i); err != nil || issued.Load() != 1 {
		t.Fatal("healthy lease was unnecessarily replaced", err)
	}
	*clock = clock.Add(41 * time.Minute)
	f.lostRenewalAck = true
	if err := f.p.MaintainStorage(ctx, i); err != nil || issued.Load() != 2 || f.renewals.Load() != 1 {
		t.Fatal("due lease did not renew and reconcile", err)
	}
	reopenProvisioner(t, f)
	if err := f.p.MaintainStorage(ctx, i); err != nil || issued.Load() != 2 {
		t.Fatal("reopen issued another lease", err)
	}
	if err := f.provider.Stop(ctx, i); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(2 * time.Hour)
	if err := f.provider.Start(ctx, i); err != nil || issued.Load() != 3 {
		t.Fatal("expired stopped lease did not refresh before boot", err)
	}
	after, err := f.p.load(ctx, i)
	if err != nil || after.Bootstrap.Browser.StorageKey != original.Bootstrap.Browser.StorageKey || after.Boot.Nonce == original.Boot.Nonce || after.Boot.StorageExpires != after.currentStorage().Expires {
		t.Fatal("automatic refresh changed profile identity or lost new expiry", err)
	}
}

func TestAutomaticStorageUncertainDeliveryIsInspectedBeforeNewIssuance(t *testing.T) {
	f, clock, issued := automaticStorageFixture(t, 1)
	i, ctx := f.instances["owner-0"], context.Background()
	if err := f.provider.Start(ctx, i); err != nil {
		t.Fatal(err)
	}
	enableFixtureRenewal(f, i)
	*clock = clock.Add(41 * time.Minute)
	f.dropRenewal = true
	if err := f.p.MaintainStorage(ctx, i); err == nil {
		t.Fatal("missing delivery accepted")
	}
	reopenProvisioner(t, f)
	for range 2 {
		if err := f.p.MaintainStorage(ctx, i); err == nil {
			t.Fatal("uncertainty discarded")
		}
	}
	if issued.Load() != 2 || f.renewals.Load() != 1 {
		t.Fatal("uncertain lease reissued or resent")
	}
}

func TestAutomaticStorageFailureCannotChangeBindingOrWakeUncertainState(t *testing.T) {
	for _, failure := range []string{"issuer", "bucket", "region", "expired", "short-lease", "foreign-credential", "attestation", "unclean-profile"} {
		t.Run(failure, func(t *testing.T) {
			f, clock, issued := automaticStorageFixture(t, 2)
			i, ctx := f.instances["owner-0"], context.Background()
			if err := f.provider.Start(ctx, i); err != nil {
				t.Fatal(err)
			}
			enableFixtureRenewal(f, i)
			original, _ := f.p.load(ctx, i)
			*clock = clock.Add(41 * time.Minute)
			issuer := f.p.issuer
			f.p.issuer = storageIssuerFunc(func(ctx context.Context, owner, audience string) (S3StoreConfig, error) {
				if failure == "issuer" {
					return S3StoreConfig{}, ErrUnavailable
				}
				storage, err := issuer.Issue(ctx, owner, audience)
				switch failure {
				case "bucket":
					storage.Bucket = "foreign-bucket"
				case "region":
					storage.Region = "eu-west-1"
				case "expired":
					storage.Expires = clock.Add(-time.Second).Unix()
				case "short-lease":
					storage.Expires = clock.Add(15 * time.Minute).Unix()
				case "foreign-credential":
					storage.AccessKeyID = f.p.owners["owner-1"].Storage.AccessKeyID
				}
				return storage, err
			})
			if failure == "attestation" {
				f.p.connect = func(string, string) (*http.Client, error) { return nil, ErrDenied }
			}
			if failure == "unclean-profile" {
				f.gates[i.Domain].cancel()
				f.states[i.ID] = "stopped"
				if err := f.provider.Start(ctx, i); err == nil {
					t.Fatal("unclean worker resumed")
				}
			} else if err := f.p.MaintainStorage(ctx, i); err == nil {
				t.Fatal("failed issuance accepted")
			}
			after, err := f.p.load(ctx, i)
			if err != nil || after.currentStorage() != original.currentStorage() || f.renewals.Load() != 0 || f.deploys.Load() != 1 {
				t.Fatal("failure replaced current lease or restarted browser", err)
			}
			if (failure == "attestation" || failure == "unclean-profile") && issued.Load() != 1 {
				t.Fatal("issued before verifying target")
			}
		})
	}
}

func automaticControllerFixture(t *testing.T, count int) (*ObjectController, *objectProvisionFixture, *time.Time, *atomic.Int32) {
	t.Helper()
	f, clock, issued := automaticStorageFixture(t, count)
	fleet, err := NewFleet(f.p.store, f.provider, count)
	if err != nil {
		t.Fatal(err)
	}
	fleet.clock = f.p.clock
	for _, i := range f.instances {
		if err = f.provider.Start(context.Background(), i); err != nil {
			t.Fatal(err)
		}
		enableFixtureRenewal(f, i)
		fleet.assignments[i.Owner] = &Assignment{Owner: i.Owner, Name: i.Name, State: "running", Instance: i, LastUsed: *clock, Users: 1}
	}
	storage := syntheticS3Config()
	storage.Bucket, storage.AccessKeyID = "controller-proof", "SYNTHETICCONTROLKEY"
	c := &ObjectController{Control: &Control{Fleet: fleet}, idle: 10 * time.Minute, provisioner: f.p, storage: storage, audience: "controller", clock: func() time.Time { return *clock }}
	workerIssuer := f.p.issuer
	c.issuer = storageIssuerFunc(func(ctx context.Context, owner, audience string) (S3StoreConfig, error) {
		if owner != "system" {
			return workerIssuer.Issue(ctx, owner, audience)
		}
		if audience != "controller" {
			return S3StoreConfig{}, ErrDenied
		}
		next := storage
		next.AccessKeyID += "renewed"
		next.Expires = clock.Add(time.Hour).Unix()
		return next, nil
	})
	c.renew = func(_ context.Context, next S3StoreConfig) error {
		if next.Bucket != storage.Bucket || next.Expires <= storage.Expires {
			return ErrDenied
		}
		return nil
	}
	return c, f, clock, issued
}

func TestAutomaticControllerMaintainsOwnLeaseAndPreservesIdleAndQuarantine(t *testing.T) {
	c, f, clock, issued := automaticControllerFixture(t, 4)
	*clock = clock.Add(41 * time.Minute)
	assignments := c.Control.Fleet.assignments
	assignments["owner-1"].Users = 0 // Already idle: stop instead of renewing.
	assignments["owner-2"].State = "quarantined"
	assignments["owner-3"].State = "stopped"
	originalLastUsed := assignments["owner-0"].LastUsed
	old := c.storage
	if err := c.MaintainStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.storage.Expires <= old.Expires || issued.Load() != 5 || f.renewals.Load() != 1 || assignments["owner-0"].LastUsed != originalLastUsed || assignments["owner-0"].Users != 1 || assignments["owner-2"].State != "quarantined" || assignments["owner-3"].State != "stopped" {
		t.Fatal("maintenance renewed the wrong workers or altered fleet lifecycle")
	}
	if err := c.MaintainStorage(context.Background()); err != nil || issued.Load() != 5 {
		t.Fatal("fresh leases renewed again", err)
	}
	assignments["owner-0"].Users = 0
	if stopped, err := c.Control.Fleet.StopIdle(context.Background(), c.idle); err != nil || stopped != 2 {
		t.Fatal("maintenance prevented idle stop", stopped, err)
	}
}

func TestAutomaticControllerOwnLeaseFailureStopsWorkerIssuance(t *testing.T) {
	c, f, clock, issued := automaticControllerFixture(t, 1)
	*clock = clock.Add(41 * time.Minute)
	original := c.storage
	c.renew = func(context.Context, S3StoreConfig) error { return ErrDenied }
	if err := c.MaintainStorage(context.Background()); !errors.Is(err, ErrUncertain) || c.storage != original || issued.Load() != 1 || f.renewals.Load() != 0 {
		t.Fatal("failed controller renewal changed state or issued worker credentials", err)
	}
}

func TestAutomaticControllerBoundsConcurrentIssuanceWithoutLeakingWorkAfterCancel(t *testing.T) {
	c, f, clock, issued := automaticControllerFixture(t, 10)
	*clock = clock.Add(41 * time.Minute)
	issuer := f.p.issuer
	var active, maximum atomic.Int32
	barrier := make(chan struct{})
	var once sync.Once
	f.p.issuer = storageIssuerFunc(func(ctx context.Context, owner, audience string) (S3StoreConfig, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		if n == 8 {
			once.Do(func() { close(barrier) })
		}
		<-ctx.Done()
		return issuer.Issue(ctx, owner, audience)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.MaintainStorage(ctx) }()
	select {
	case <-barrier:
		cancel()
	case <-ctx.Done():
		t.Fatal("independent owners serialized or maintenance stalled")
	}
	if err := <-done; err == nil || maximum.Load() != 8 || active.Load() != 0 || issued.Load() != 10 || f.renewals.Load() != 0 {
		t.Fatal("maintenance exceeded concurrency or leaked canceled issuance", err)
	}
}
