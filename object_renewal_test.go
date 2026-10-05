package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func renewalBody(t *testing.T, f *bootFixture) []byte {
	t.Helper()
	s := bootStatus(t, f.gate)
	c := f.config.Storage
	c.AccessKeyID = "RENEWEDSYNTHETICACCESSKEY"
	c.Expires = time.Now().Add(2 * time.Hour).Unix()
	raw, _ := json.Marshal(ObjectStorageRenewal{1, s.Digest, s.StorageGeneration + 1, s.StorageDigest, c})
	return raw
}

func renewalPost(g *ObjectBootGate, token string, raw []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/storage", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	g.ServeHTTP(out, r)
	return out
}

func awaitRenewal(t *testing.T, g *ObjectBootGate) ObjectBootStatus {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		s := bootStatus(t, g)
		if s.StorageState != "renewing" {
			return s
		}
		select {
		case <-deadline:
			t.Fatal("renewal did not finish")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestObjectStorageRenewalRequiresAuthorityPurposeAndLease(t *testing.T) {
	f := readyBootFixture(t)
	var calls atomic.Int32
	f.gate.renew = func(context.Context, *Worker, S3StoreConfig) error { calls.Add(1); return nil }
	for _, mode := range []string{"execution-key", "bootstrap-token", "drain-token", "wrong-nonce", "wrong-boot", "wrong-previous", "wrong-generation", "expired-grant", "long-grant", "expired-lease", "short-lease", "long-lease", "no-expiry", "no-session", "body-change", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			raw := renewalBody(t, f)
			var c ObjectStorageRenewal
			json.Unmarshal(raw, &c)
			key, nonce, expires := f.key, bootStatus(t, f.gate).Nonce, time.Now().Add(time.Minute)
			switch mode {
			case "execution-key":
				key = f.exec
			case "wrong-nonce":
				nonce = strings.Repeat("A", 43)
			case "wrong-boot":
				c.BootDigest = strings.Repeat("f", 64)
			case "wrong-previous":
				c.Previous = strings.Repeat("e", 64)
			case "wrong-generation":
				c.Generation++
			case "expired-grant":
				expires = time.Now().Add(-time.Minute)
			case "long-grant":
				expires = time.Now().Add(3 * time.Minute)
			case "expired-lease":
				c.Storage.Expires = time.Now().Add(-time.Hour).Unix()
			case "short-lease":
				c.Storage.Expires = time.Now().Add(5 * time.Minute).Unix()
			case "long-lease":
				c.Storage.Expires = time.Now().Add(13 * time.Hour).Unix()
			case "no-expiry":
				c.Storage.Expires = 0
			case "no-session":
				c.Storage.SessionToken = ""
			}
			raw, _ = json.Marshal(c)
			if mode == "unknown-field" {
				raw = append([]byte(`{"owner":"bob",`), raw[1:]...)
			}
			token, err := SignObjectStorageRenewal(key, nonce, raw, expires)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "bootstrap-token" {
				token, _ = SignObjectBootstrap(key, nonce, raw, expires)
			}
			if mode == "drain-token" {
				token, _ = SignObjectDrain(key, bootStatus(t, f.gate), expires)
			}
			if mode == "body-change" {
				raw = append(raw, ' ')
			}
			response := renewalPost(f.gate, token, raw)
			if response.Code != 403 && response.Code != 409 {
				t.Fatal("unauthorized renewal accepted", response.Code)
			}
			if calls.Load() != 0 || bootStatus(t, f.gate).StorageGeneration != 0 {
				t.Fatal("denied request changed storage")
			}
		})
	}
}

func TestObjectStorageRenewalSingleClaimAndStaleTimer(t *testing.T) {
	f := readyBootFixture(t)
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	f.gate.renew = func(context.Context, *Worker, S3StoreConfig) error {
		calls.Add(1)
		close(started)
		<-release
		return nil
	}
	before := bootStatus(t, f.gate)
	raw := renewalBody(t, f)
	token, _ := SignObjectStorageRenewal(f.key, before.Nonce, raw, time.Now().Add(time.Minute))
	response := renewalPost(f.gate, token, raw)
	if response.Code != 202 {
		t.Fatal("renewal rejected", response.Code)
	}
	<-started
	if renewalPost(f.gate, token, raw).Code != 409 {
		t.Fatal("claimed renewal replayed")
	}
	for _, secret := range []string{f.config.Storage.Bucket, f.config.Storage.SecretAccessKey, f.config.Storage.SessionToken, "RENEWEDSYNTHETICACCESSKEY"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("storage secret exposed")
		}
	}
	close(release)
	after := awaitRenewal(t, f.gate)
	if after.State != "ready" || after.StorageState != "ready" || after.StorageExpires <= before.StorageExpires || calls.Load() != 1 {
		t.Fatal("renewal did not finish once", after)
	}
	if renewalPost(f.gate, token, raw).Code != 409 {
		t.Fatal("completed renewal replayed")
	}
	f.gate.expireStorage(before.StorageExpires, time.Unix(before.StorageExpires, 0))
	if bootStatus(t, f.gate).State != "ready" {
		t.Fatal("stale timer stopped renewed worker")
	}
}

func TestObjectStorageRenewalFailurePreservesExpiryAndCheckpoints(t *testing.T) {
	f := readyBootFixture(t)
	f.gate.renew = func(context.Context, *Worker, S3StoreConfig) error { return ErrDenied }
	before := bootStatus(t, f.gate)
	raw := renewalBody(t, f)
	token, _ := SignObjectStorageRenewal(f.key, before.Nonce, raw, time.Now().Add(time.Minute))
	if renewalPost(f.gate, token, raw).Code != 202 {
		t.Fatal("claim rejected")
	}
	after := awaitRenewal(t, f.gate)
	if after.StorageState != "failed" || after.State != "ready" || after.StorageExpires != before.StorageExpires {
		t.Fatal("failure changed existing lease")
	}
	f.gate.expireStorage(before.StorageExpires, time.Unix(before.StorageExpires, 0).Add(-storageDrainLead))
	if bootStatus(t, f.gate).State != "stopped" || !f.driver.clean.Load() {
		t.Fatal("expired lease did not checkpoint cleanly")
	}
	r := httptest.NewRecorder()
	f.gate.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/v1/exec", strings.NewReader(`{}`)))
	if r.Code != 503 {
		t.Fatal("new work accepted after expiry drain")
	}
	if renewalPost(f.gate, token, raw).Code != 409 {
		t.Fatal("stopped worker renewed")
	}
}

func renewalStorageFixture(t *testing.T) (*SealedStore, *testBlobBackend, *http.Client, S3StoreConfig) {
	t.Helper()
	s, backing, _ := testRemoteStore(t)
	c := syntheticS3Config()
	client := &http.Client{Transport: s3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		object := path.Base(r.URL.Path)
		if r.Method == http.MethodGet {
			raw, version, err := backing.Get(r.Context(), object)
			if err != nil {
				return s3Response(r, 404, `<Error><Code>NoSuchKey</Code></Error>`, ""), nil
			}
			return s3Response(r, 200, string(raw), version), nil
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		version, err := backing.Put(r.Context(), object, raw, r.Header.Get("If-Match"))
		if err != nil {
			return s3Response(r, 412, `<Error><Code>PreconditionFailed</Code></Error>`, ""), nil
		}
		return s3Response(r, 200, "", version), nil
	})}
	b, err := newS3BlobBackend(c, "alice", "worker", client)
	if err != nil {
		t.Fatal(err)
	}
	s.remote.backend = b
	c.AccessKeyID = "RENEWEDSYNTHETICACCESSKEY"
	c.Expires = time.Now().Add(2 * time.Hour).Unix()
	return s, backing, client, c
}

func TestStorageRenewalRetainsCASAndQuarantine(t *testing.T) {
	ctx := context.Background()
	s, backing, client, c := renewalStorageFixture(t)
	if err := s.Put("alice", "execution", "retained", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("alice", "execution", "retained"); err != nil {
		t.Fatal(err)
	}
	_, slot, _, _ := s.binding("alice", "execution", "retained")
	version := s.remote.versions[path.Base(slot)]
	var renewedCalls atomic.Int32
	inner := client.Transport
	client.Transport = s3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.Header.Get("Authorization"), "Credential="+c.AccessKeyID+"/") {
			t.Fatal("old credential retained")
		}
		renewedCalls.Add(1)
		return inner.RoundTrip(r)
	})
	if err := s.renewS3Credentials(ctx, "alice", "worker", c, client); err != nil {
		t.Fatal(err)
	}
	if s.remote.versions[path.Base(slot)] != version || renewedCalls.Load() != 1 {
		t.Fatal("renewal discarded observed version")
	}
	// A concurrent writer after the old read must still defeat the next CAS.
	backing.Put(ctx, path.Base(slot), []byte("competing-write"), version)
	if err := s.Put("alice", "execution", "retained", []byte("new")); err != ErrUncertain || !s.remote.blocked {
		t.Fatal("renewal hid conflicting write")
	}
	before := renewedCalls.Load()
	if err := s.renewS3Credentials(ctx, "alice", "worker", c, client); err == nil || renewedCalls.Load() != before {
		t.Fatal("renewal reset quarantine")
	}
}

func TestStorageRenewalRejectsIdentityAndLocationChanges(t *testing.T) {
	for _, mode := range []string{"bucket", "region", "owner", "audience", "missing-identity", "wrong-identity", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s, backing, client, c := renewalStorageFixture(t)
			old := s.remote.backend
			owner, audience := "alice", "worker"
			switch mode {
			case "bucket":
				c.Bucket = "other-bucket"
			case "region":
				c.Region = "us-west-2"
			case "owner":
				owner = "bob"
			case "audience":
				audience = "other-worker"
			case "missing-identity":
				delete(backing.objects, "identity.sealed")
			case "wrong-identity":
				backing.objects["identity.sealed"] = testBlob{[]byte("foreign-ciphertext"), `"v2"`}
			case "expired":
				c.Expires = time.Now().Add(-time.Hour).Unix()
			}
			writes := backing.writes
			if err := s.renewS3Credentials(context.Background(), owner, audience, c, client); err == nil || s.remote.backend != old || backing.writes != writes {
				t.Fatal("renewal replaced identity or backend")
			}
		})
	}
}

func TestExpiredStorageCredentialNeverReachesNetwork(t *testing.T) {
	c := syntheticS3Config()
	c.Expires = time.Now().Add(-time.Second).Unix()
	var calls atomic.Int32
	b, err := newS3BlobBackend(c, "alice", "worker", &http.Client{Transport: s3RoundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, ErrUnavailable })})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Get(context.Background(), "identity.sealed"); err == nil || calls.Load() != 0 {
		t.Fatal("expired credentials transmitted")
	}
}
