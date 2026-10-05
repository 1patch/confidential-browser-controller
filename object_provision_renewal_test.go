package browser

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func provisionLease(f *objectProvisionFixture, owner string, minutes int) S3StoreConfig {
	c := f.p.owners[owner].Storage
	c.AccessKeyID += "renewed"
	c.SessionToken = "synthetic-session-token"
	c.Expires += int64(time.Duration(minutes) * time.Minute / time.Second)
	return c
}

func renewalFixture(t *testing.T) (*objectProvisionFixture, Instance) {
	t.Helper()
	f := newObjectProvisionFixture(t, 2)
	i := f.instances["owner-0"]
	if err := f.provider.Start(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	// Worker IAM/identity validation is independently covered with real S3.
	// This fixture exercises controller receipts and cloud lifecycle only.
	f.gates[i.Domain].renew = func(_ context.Context, _ *Worker, c S3StoreConfig) error {
		if strings.HasSuffix(c.AccessKeyID, "rejected") {
			return ErrDenied
		}
		return nil
	}
	return f, i
}

func reopenProvisioner(t *testing.T, f *objectProvisionFixture) {
	t.Helper()
	store, err := newRemoteSealedStore(context.Background(), "system", "controller", f.controlKey, f.control, false)
	if err != nil {
		t.Fatal(err)
	}
	var issuers []StorageLeaseIssuer
	if f.p.issuer != nil {
		issuers = append(issuers, f.p.issuer)
	}
	p, err := NewObjectProvisioner(f.provider, store, f.p.key, f.p.owners, issuers...)
	if err != nil {
		t.Fatal(err)
	}
	p.open, p.connect, p.clock = f.p.open, f.p.connect, f.p.clock
	f.p, f.provider.Provisioner = p, p
}

func TestObjectProvisionerRenewalPreservesBootAndUsesNewCredentialsAcrossStopWake(t *testing.T) {
	f, i := renewalFixture(t)
	ctx := context.Background()
	original, err := f.p.load(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	if f.execute(i.Owner, "retained-renewal-action") != 200 {
		t.Fatal("initial action failed")
	}
	for _, minutes := range []int{60, 90} {
		storage := provisionLease(f, i.Owner, minutes)
		f.lostRenewalAck = true
		if err = f.p.RenewStorage(ctx, i, storage); err != nil {
			t.Fatal("lost renewal reply was not reconciled", err)
		}
		reopenProvisioner(t, f)
		if err = f.p.RenewStorage(ctx, i, storage); err != nil {
			t.Fatal("completed renewal was not recognized", err)
		}
		current, err := f.p.load(ctx, i)
		if err != nil || current.Renewal != nil || current.currentStorage() != storage || current.Boot.Digest != original.Boot.Digest || current.Boot.Nonce != original.Boot.Nonce || current.Bootstrap.Browser.StorageKey != original.Bootstrap.Browser.StorageKey {
			t.Fatal("renewal changed bootstrap/key or lost credential state", err)
		}
		if f.execute(i.Owner, "retained-renewal-action") != 200 {
			t.Fatal("completed action unavailable")
		}
	}
	if f.renewals.Load() != 2 || f.effects[i.Owner].Load() != 1 {
		t.Fatal("renewal or browser action replayed")
	}
	latest, _ := f.p.load(ctx, i)
	open := f.p.open
	f.p.open = func(ctx context.Context, c ObjectBootstrap, create bool) (*SealedStore, error) {
		if c.Storage != latest.currentStorage() || create {
			t.Error("old credentials or reinitialization used after renewal")
			return nil, ErrDenied
		}
		return open(ctx, c, false)
	}
	if err = f.provider.Stop(ctx, i); err != nil {
		t.Fatal("drain did not use renewed credentials", err)
	}
	reopenProvisioner(t, f)
	if err = f.provider.Start(ctx, i); err != nil {
		t.Fatal("next boot did not use renewed credentials", err)
	}
	woken, _ := f.p.load(ctx, i)
	if woken.Boot.Nonce == original.Boot.Nonce || woken.Boot.StorageGeneration != 0 || woken.Bootstrap.Storage != latest.currentStorage() || woken.Bootstrap.Browser.StorageKey != original.Bootstrap.Browser.StorageKey || f.execute(i.Owner, "retained-renewal-action") != 200 || f.effects[i.Owner].Load() != 1 {
		t.Fatal("wake changed identity, retained old generation or replayed an action")
	}
	if err = f.p.RenewStorage(ctx, i, latest.currentStorage()); err != nil || f.renewals.Load() != 2 {
		t.Fatal("wake forgot committed credentials or resent them", err)
	}
}

func TestObjectProvisionerRenewalFailureRetainsOldLeaseAndNextGeneration(t *testing.T) {
	f, i := renewalFixture(t)
	ctx := context.Background()
	old, _ := f.p.load(ctx, i)
	rejected := provisionLease(f, i.Owner, 60)
	rejected.AccessKeyID += "rejected"
	if err := f.p.RenewStorage(ctx, i, rejected); !errors.Is(err, ErrDenied) {
		t.Fatal("failure not reported", err)
	}
	r, err := f.p.load(ctx, i)
	if err != nil || r.Renewal != nil || r.currentStorage() != old.currentStorage() || r.Boot.StorageState != "failed" || r.Boot.StorageGeneration != 1 {
		t.Fatal("failed renewal replaced current lease or lost generation", err)
	}
	if err = f.provider.Verify(ctx, i); err != nil {
		t.Fatal("old valid lease unavailable", err)
	}
	if err = f.p.RenewStorage(ctx, i, provisionLease(f, i.Owner, 60)); err != nil {
		t.Fatal("fresh renewal after confirmed failure failed", err)
	}
	r, _ = f.p.load(ctx, i)
	if r.Boot.StorageGeneration != 2 || f.renewals.Load() != 2 {
		t.Fatal("failed generation reused")
	}
}

func TestObjectProvisionerUncertainRenewalCannotResendOrPowerOffAfterRestart(t *testing.T) {
	for _, reason := range []string{"missing-delivery", "uncertain-reservation", "pending-worker", "uncertain-commit"} {
		t.Run(reason, func(t *testing.T) {
			f, i := renewalFixture(t)
			storage := provisionLease(f, i.Owner, 60)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if reason == "missing-delivery" {
				f.dropRenewal = true
			}
			if reason == "uncertain-reservation" {
				f.control.mu.Lock()
				f.control.failAt, f.control.commitFailed = f.control.writes+1, true
				f.control.mu.Unlock()
			}
			release := make(chan struct{})
			if reason == "pending-worker" || reason == "uncertain-commit" {
				f.gates[i.Domain].renew = func(ctx context.Context, _ *Worker, _ S3StoreConfig) error {
					if reason == "pending-worker" {
						cancel() // The worker already claimed the retained generation.
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
					} else {
						f.control.mu.Lock()
						f.control.failAt, f.control.commitFailed = f.control.writes+1, true
						f.control.mu.Unlock()
					}
					return nil
				}
			}
			err := f.p.RenewStorage(ctx, i, storage)
			cancel()
			if err == nil {
				t.Fatal("uncertainty reported as success")
			}
			reopenProvisioner(t, f)
			if reason == "pending-worker" {
				close(release)
			}
			if reason == "pending-worker" || reason == "uncertain-commit" {
				if err = f.p.ReconcileStorage(context.Background(), i); err != nil {
					t.Fatal("completed receipt did not reconcile", err)
				}
				if err = f.p.RenewStorage(context.Background(), i, storage); err != nil {
					t.Fatal("completed lease unavailable", err)
				}
			} else {
				if err = f.p.RenewStorage(context.Background(), i, storage); err == nil {
					t.Fatal("unconfirmed delivery accepted")
				}
				if err = f.provider.Stop(context.Background(), i); err == nil || f.states[i.ID] != "running" || f.drains.Load() != 0 {
					t.Fatal("uncertain renewal allowed power-off", err, f.states[i.ID], f.drains.Load())
				}
			}
			expected := int32(1)
			if reason == "uncertain-reservation" {
				expected = 0
			}
			if f.renewals.Load() != expected {
				t.Fatal("renewal resent after reopening")
			}
		})
	}
}

func TestObjectProvisionerStoppedRefreshValidatesClosedIdentityAndPersistsBeforeWake(t *testing.T) {
	f, i := renewalFixture(t)
	ctx := context.Background()
	storage := provisionLease(f, i.Owner, 60)
	if err := f.p.RefreshStoppedStorage(ctx, i, storage); err == nil {
		t.Fatal("running worker credentials replaced locally")
	}
	if err := f.provider.Stop(ctx, i); err != nil {
		t.Fatal(err)
	}
	old, _ := f.p.load(ctx, i)
	open := f.p.open
	denied := true
	f.p.open = func(ctx context.Context, c ObjectBootstrap, create bool) (*SealedStore, error) {
		if create {
			t.Fatal("refresh tried to initialize missing identity")
		}
		if denied {
			return nil, ErrDenied
		}
		return open(ctx, c, false)
	}
	if err := f.p.RefreshStoppedStorage(ctx, i, storage); err == nil {
		t.Fatal("unauthenticated profile accepted")
	}
	after, _ := f.p.load(ctx, i)
	if after.currentStorage() != old.currentStorage() {
		t.Fatal("failed authentication changed stored credentials")
	}
	denied = false
	if err := f.p.RefreshStoppedStorage(ctx, i, storage); err != nil {
		t.Fatal(err)
	}
	reopenProvisioner(t, f)
	after, err := f.p.load(ctx, i)
	if err != nil || after.Bootstrap.Storage != storage || after.LastNonce != old.LastNonce || after.Bootstrap.Browser.StorageKey != old.Bootstrap.Browser.StorageKey || f.deploys.Load() != 1 || f.posts.Load() != 1 {
		t.Fatal("refresh changed identity, forgot prior boot or woke VM", err)
	}
	if err = f.provider.Start(ctx, i); err != nil {
		t.Fatal("refreshed stopped worker did not wake", err)
	}
}

func TestObjectProvisionerRenewalRejectsChangedLocationAndCompetingController(t *testing.T) {
	for _, reason := range []string{"bucket", "region", "owner-credential", "expired", "competing-write", "out-of-band"} {
		t.Run(reason, func(t *testing.T) {
			f, i := renewalFixture(t)
			storage := provisionLease(f, i.Owner, 60)
			switch reason {
			case "bucket":
				storage.Bucket = "foreign-bucket"
			case "region":
				storage.Region = "eu-west-1"
			case "owner-credential":
				storage.AccessKeyID = f.p.owners["owner-1"].Storage.AccessKeyID
			case "expired":
				storage.Expires = time.Now().Unix()
			case "out-of-band":
				g := f.gates[i.Domain]
				g.mu.Lock()
				g.status.StorageGeneration, g.status.StorageDigest, g.status.StorageState = 1, strings.Repeat("a", 64), "failed"
				g.mu.Unlock()
				if err := f.provider.Verify(context.Background(), i); err == nil {
					t.Fatal("unknown renewal accepted by verification")
				}
			case "competing-write":
				other, err := newRemoteSealedStore(context.Background(), "system", "controller", f.controlKey, f.control, false)
				if err != nil {
					t.Fatal(err)
				}
				connect := f.p.connect
				var once sync.Once
				f.p.connect = func(domain, pin string) (*http.Client, error) {
					once.Do(func() {
						raw, err := other.Get("system", "object-provision", i.Name)
						if err != nil || other.Put("system", "object-provision", i.Name, raw) != nil {
							t.Fatal("competing write fixture failed", err)
						}
						clear(raw)
					})
					return connect(domain, pin)
				}
			}
			if err := f.p.RenewStorage(context.Background(), i, storage); err == nil || f.renewals.Load() != 0 {
				t.Fatal("invalid renewal sent")
			}
		})
	}
}

func TestObjectProvisionerRejectsCorruptRenewalCommitment(t *testing.T) {
	f, i := renewalFixture(t)
	f.dropRenewal = true
	if err := f.p.RenewStorage(context.Background(), i, provisionLease(f, i.Owner, 60)); err == nil {
		t.Fatal("missing delivery accepted")
	}
	raw, _ := f.p.store.Get("system", "object-provision", i.Name)
	var record objectProvisionRecord
	json.Unmarshal(raw, &record)
	record.Renewal.Storage.SecretAccessKey = "different-synthetic-key"
	raw, _ = json.Marshal(record)
	if err := f.p.store.Put("system", "object-provision", i.Name, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.load(context.Background(), i); err == nil {
		t.Fatal("credentials no longer matched retained commitment")
	}
}

func TestObjectProvisionerWorkerExpiryCheckpointAllowsVerifiedCloudStopAndRefresh(t *testing.T) {
	f, i := renewalFixture(t)
	ctx := context.Background()
	storage := provisionLease(f, i.Owner, 60)
	if err := f.p.RenewStorage(ctx, i, storage); err != nil {
		t.Fatal(err)
	}
	gate := f.gates[i.Domain]
	gate.expireStorage(storage.Expires, time.Unix(storage.Expires, 0))
	if bootStatus(t, gate).State != "stopped" {
		t.Fatal("worker did not checkpoint")
	}
	if err := f.provider.Stop(ctx, i); err != nil || f.states[i.ID] != "stopped" || f.drains.Load() != 0 {
		t.Fatal("controller failed to verify independent expiry checkpoint", err)
	}
	// The profile remains closed while a stopped lease expires. The next
	// trusted issuer can refresh authentication without replacing that profile.
	r, _ := f.p.load(ctx, i)
	expired := r.currentStorage()
	expired.Expires = time.Now().Add(-time.Minute).Unix()
	r.Storage, r.Bootstrap.Storage = &expired, expired
	if err := f.p.save(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	if err := f.p.RefreshStoppedStorage(ctx, i, provisionLease(f, i.Owner, 90)); err != nil {
		t.Fatal("expired lease prevented authenticated refresh", err)
	}
	if err := f.provider.Start(ctx, i); err != nil {
		t.Fatal("refreshed worker could not wake", err)
	}
}
