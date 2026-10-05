package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type objectControllerFixture struct {
	location ObjectControllerLocation
	config   ObjectControllerConfig
	backing  *testBlobBackend
	appKey   ed25519.PrivateKey
}

func newObjectControllerFixture(t *testing.T, count int) *objectControllerFixture {
	t.Helper()
	app, appKey, _ := ed25519.GenerateKey(rand.Reader)
	worker, workerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	rand.Read(key)
	f := &objectControllerFixture{backing: newTestBlobs(), appKey: appKey}
	f.location = ObjectControllerLocation{Version: 1, Audience: "controller", StorageKey: base64.StdEncoding.EncodeToString(key), Storage: syntheticS3Config()}
	f.location.Storage.Bucket, f.location.Storage.AccessKeyID = "browser-controller-proof", "SYNTHETICCONTROLLER"
	f.config = ObjectControllerConfig{Version: 1, Audience: "controller", ExecutePublicKey: base64.StdEncoding.EncodeToString(app), WorkerPrivateKey: base64.StdEncoding.EncodeToString(workerKey.Seed()), BootstrapPrivateKey: base64.StdEncoding.EncodeToString(issuer.Seed()), AdminKey: "admin_synthetic", WorkerRepository: "example/browser@v1@sha256:" + strings.Repeat("a", 64), DomainSuffix: "proof.containers.tinfoil.dev", Owners: map[string]ObjectOwnerPolicy{}, Capacity: count, IdleMinutes: 10}
	for index := range count {
		owner := fmt.Sprintf("owner-%d", index)
		policy := ObjectOwnerPolicy{Browser: testBootstrap(t, owner), Storage: syntheticS3Config()}
		policy.Browser.Audience, policy.Browser.StorageKey = "", ""
		policy.Browser.ExecutePublicKey = base64.StdEncoding.EncodeToString(worker)
		policy.Storage.Bucket, policy.Storage.AccessKeyID = "browser-proof-"+owner, "SYNTHETIC"+owner
		policy.Storage.SessionToken = strings.Repeat("synthetic", 200)
		f.config.Owners[owner] = policy
	}
	f.digest()
	return f
}

func (f *objectControllerFixture) digest() {
	raw, _ := json.Marshal(f.config)
	f.location.Digest = objectBootDigest(raw)
}

func (f *objectControllerFixture) open(ctx context.Context, location ObjectControllerLocation, initialize bool) (*SealedStore, error) {
	key, _ := base64.StdEncoding.DecodeString(location.StorageKey)
	defer clear(key)
	return newRemoteSealedStore(ctx, "system", location.Audience, key, f.backing, initialize)
}

func TestObjectControllerEncryptedEnrollmentAndRestart(t *testing.T) {
	f := newObjectControllerFixture(t, 100)
	ctx := context.Background()
	raw, _ := json.Marshal(f.config)
	if len(raw) <= 128<<10 {
		t.Fatal("fixture must exceed Linux's per-variable environment limit")
	}
	if err := provisionObjectController(ctx, f.location, f.config, f.open); err != nil {
		t.Fatal(err)
	}
	writes := f.backing.writes
	if err := provisionObjectController(ctx, f.location, f.config, f.open); err != nil || f.backing.writes != writes {
		t.Fatal("identical enrollment was not read-only", err)
	}
	for _, blob := range f.backing.objects {
		for _, secret := range []string{f.config.AdminKey, f.config.WorkerPrivateKey, f.config.BootstrapPrivateKey, f.config.Owners["owner-0"].Storage.SessionToken} {
			if bytes.Contains(blob.data, []byte(secret)) {
				t.Fatal("enrollment plaintext escaped encryption")
			}
		}
	}
	c, err := loadObjectController(ctx, f.location, f.open)
	if err != nil || c.Control.Fleet.limit != 100 || len(c.Control.AllowedOwners) != 100 {
		t.Fatal("100-owner enrollment failed", err)
	}
	if f.backing.writes != writes {
		t.Fatal("service startup mutated storage")
	}
	fleet := c.Control.Fleet
	i := Instance{Owner: "owner-0", Name: "browser-proof", ID: "00000000-0000-0000-0000-000000000001", Domain: "browser-proof." + f.config.DomainSuffix, Repository: f.config.WorkerRepository}
	fleet.assignments[i.Owner] = &Assignment{Owner: i.Owner, Name: i.Name, State: "running", Instance: i, LastUsed: time.Now(), Users: 1}
	if err = fleet.save(); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadObjectController(ctx, f.location, f.open)
	if err != nil || restarted.Control.Fleet.assignments[i.Owner].State != "quarantined" {
		t.Fatal("restart silently resumed a browser lease", err)
	}
	if _, _, err = restarted.Control.Fleet.Lease(i.Owner); err == nil {
		t.Fatal("quarantined browser remained executable")
	}
}

func configureControllerIssuer(f *objectControllerFixture) {
	c := syntheticStorageIssuer()
	c.Roles = map[string]StorageIssuerRole{"system": {ARN: "arn:aws:iam::123456789012:role/browser-controller", Bucket: f.location.Storage.Bucket, Region: f.location.Storage.Region}}
	for owner, policy := range f.config.Owners {
		c.Roles[owner] = StorageIssuerRole{ARN: "arn:aws:iam::123456789012:role/browser-" + owner, Bucket: policy.Storage.Bucket, Region: policy.Storage.Region}
	}
	f.config.StorageIssuer = &c
	f.digest()
}

func TestObjectControllerIssuerEnrollmentIsEncryptedAndBoundToAllStorageRoles(t *testing.T) {
	f := newObjectControllerFixture(t, 100)
	configureControllerIssuer(f)
	if err := provisionObjectController(context.Background(), f.location, f.config, f.open); err != nil {
		t.Fatal(err)
	}
	c, err := loadObjectController(context.Background(), f.location, f.open)
	if err != nil || c.issuer == nil || c.provisioner.issuer == nil || c.Control.maintain == nil {
		t.Fatal("automatic maintenance was not connected", err)
	}
	for _, blob := range f.backing.objects {
		if bytes.Contains(blob.data, []byte(f.config.StorageIssuer.Authority.SecretAccessKey)) {
			t.Fatal("issuer authority escaped encryption")
		}
	}
	for _, change := range []string{"missing-owner", "extra-owner", "missing-controller", "worker-bucket", "controller-bucket", "source-worker-key", "source-controller-key"} {
		t.Run(change, func(t *testing.T) {
			f := newObjectControllerFixture(t, 2)
			configureControllerIssuer(f)
			issuer := f.config.StorageIssuer
			switch change {
			case "missing-owner":
				delete(issuer.Roles, "owner-0")
			case "extra-owner":
				issuer.Roles["foreign"] = StorageIssuerRole{ARN: "arn:aws:iam::123456789012:role/foreign", Bucket: "foreign-bucket", Region: "us-east-1"}
			case "missing-controller":
				delete(issuer.Roles, "system")
			case "worker-bucket":
				role := issuer.Roles["owner-0"]
				role.Bucket = "foreign-bucket"
				issuer.Roles["owner-0"] = role
			case "controller-bucket":
				role := issuer.Roles["system"]
				role.Bucket = "foreign-bucket"
				issuer.Roles["system"] = role
			case "source-worker-key":
				issuer.Authority.AccessKeyID = f.config.Owners["owner-0"].Storage.AccessKeyID
			case "source-controller-key":
				issuer.Authority.AccessKeyID = f.location.Storage.AccessKeyID
			}
			f.digest()
			if err := provisionObjectController(context.Background(), f.location, f.config, f.open); err == nil {
				t.Fatal("unsafe issuer enrollment accepted")
			}
		})
	}
}

func TestObjectControllerMissingOrSubstitutedStateFailsClosed(t *testing.T) {
	for _, change := range []string{"missing-identity", "missing-enrollment", "wrong-key", "wrong-audience", "wrong-digest", "corrupt-enrollment", "foreign-purpose"} {
		t.Run(change, func(t *testing.T) {
			f := newObjectControllerFixture(t, 1)
			ctx := context.Background()
			if change != "missing-identity" {
				if err := provisionObjectController(ctx, f.location, f.config, f.open); err != nil {
					t.Fatal(err)
				}
			}
			store, _ := f.open(ctx, f.location, false)
			var slot string
			if store != nil {
				_, path, _, _ := store.binding("system", "controller", "bootstrap")
				slot = filepath.Base(path)
			}
			switch change {
			case "missing-enrollment":
				delete(f.backing.objects, slot)
			case "wrong-key":
				f.location.StorageKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			case "wrong-audience":
				f.location.Audience = "another-controller"
			case "wrong-digest":
				f.location.Digest = strings.Repeat("0", 64)
			case "corrupt-enrollment":
				blob := f.backing.objects[slot]
				blob.data[len(blob.data)-1] ^= 1
			case "foreign-purpose":
				f.backing.objects[slot] = f.backing.objects["identity.sealed"]
			}
			writes := f.backing.writes
			if _, err := loadObjectController(ctx, f.location, f.open); err == nil || f.backing.writes != writes {
				t.Fatal("startup repaired or accepted missing/substituted state")
			}
		})
	}
}

func TestObjectControllerEnrollmentCannotBeReplaced(t *testing.T) {
	f := newObjectControllerFixture(t, 1)
	ctx := context.Background()
	// Simulate a successful encrypted enrollment write whose acknowledgment is lost.
	f.backing.failAt, f.backing.commitFailed = 2, true
	if err := provisionObjectController(ctx, f.location, f.config, f.open); err == nil {
		t.Fatal("lost acknowledgment reported success")
	}
	writes := f.backing.writes
	if err := provisionObjectController(ctx, f.location, f.config, f.open); err != nil || f.backing.writes != writes {
		t.Fatal("lost acknowledgment did not reconcile read-only", err)
	}
	f.config.AdminKey = "admin_changed"
	f.digest()
	if err := provisionObjectController(ctx, f.location, f.config, f.open); err == nil || f.backing.writes != writes {
		t.Fatal("changed enrollment replaced immutable state")
	}
	if _, err := loadObjectController(ctx, f.location, f.open); err == nil {
		t.Fatal("changed commitment accepted old enrollment")
	}
}

func TestObjectControllerAuthorityAndStorageSeparation(t *testing.T) {
	changes := map[string]func(*objectControllerFixture){
		"app-as-worker": func(f *objectControllerFixture) {
			f.config.ExecutePublicKey = f.config.Owners["owner-0"].Browser.ExecutePublicKey
		},
		"shared-signers":     func(f *objectControllerFixture) { f.config.BootstrapPrivateKey = f.config.WorkerPrivateKey },
		"shared-storage-key": func(f *objectControllerFixture) { f.location.StorageKey = f.config.WorkerPrivateKey },
		"shared-bucket": func(f *objectControllerFixture) {
			f.location.Storage.Bucket = f.config.Owners["owner-0"].Storage.Bucket
		},
		"shared-storage-authority": func(f *objectControllerFixture) {
			f.location.Storage.AccessKeyID = f.config.Owners["owner-0"].Storage.AccessKeyID
		},
		"foreign-audience":   func(f *objectControllerFixture) { f.config.Audience = "another-controller" },
		"unpinned-release":   func(f *objectControllerFixture) { f.config.WorkerRepository = "example/browser@latest" },
		"oversized-capacity": func(f *objectControllerFixture) { f.config.Capacity = 101 },
		"empty-enrollment":   func(f *objectControllerFixture) { f.config.Owners = nil },
		"app-as-operator": func(f *objectControllerFixture) {
			p := f.config.Owners["owner-0"]
			p.Browser.SecretsPublicKey = f.config.ExecutePublicKey
			f.config.Owners["owner-0"] = p
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newObjectControllerFixture(t, 1)
			change(f)
			f.digest()
			if err := provisionObjectController(context.Background(), f.location, f.config, f.open); err == nil || f.backing.writes != 0 {
				t.Fatal("invalid authority reached persistent provisioning")
			}
		})
	}
}

func TestObjectControllerRejectsUnknownOwnersAndWrongSigningKeys(t *testing.T) {
	f := newObjectControllerFixture(t, 1)
	ctx := context.Background()
	if err := provisionObjectController(ctx, f.location, f.config, f.open); err != nil {
		t.Fatal(err)
	}
	c, err := loadObjectController(ctx, f.location, f.open)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		owner string
		key   ed25519.PrivateKey
	}{{"unregistered-owner", f.appKey}, {"owner-0", c.Control.WorkerKey}} {
		token, err := SignCapability(tc.key, Principal{Owner: tc.owner, Audience: f.config.Audience, Scope: "prepare", ID: "request", Expires: time.Now().Add(time.Minute).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/prepare", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		c.Control.ServeHTTP(out, r)
		if out.Code != 403 || len(c.Control.Fleet.assignments) != 0 || strings.Contains(out.Body.String(), f.config.AdminKey) {
			t.Fatal("untrusted request reached cloud provisioning or disclosed enrollment")
		}
	}
}
