package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const storageDrainLead = 5 * time.Minute

// ObjectStorageRenewal replaces only storage authentication, never an owner,
// bucket, region, encryption key, browser policy or execution journal. Previous
// identifies the last accepted renewal, including a failed one. A lost reply
// must be inspected, not resubmitted. Each fresh process starts generation zero.
type ObjectStorageRenewal struct {
	Version    int           `json:"version"`
	BootDigest string        `json:"bootDigest"`
	Generation uint64        `json:"generation"`
	Previous   string        `json:"previous"`
	Storage    S3StoreConfig `json:"storage"`
}

func storageLeaseUsable(c S3StoreConfig, now time.Time) bool {
	return c.Expires == 0 || (c.SessionToken != "" && c.Expires > now.Add(2*storageDrainLead).Unix() && c.Expires <= now.Add(12*time.Hour).Unix())
}

// SignObjectStorageRenewal is exclusively a bootstrap-operator operation. The
// caller must attest the exact target and reserve the nonce/body before sending.
func SignObjectStorageRenewal(key ed25519.PrivateKey, nonce string, raw []byte, expires time.Time) (string, error) {
	n, err := base64.RawURLEncoding.DecodeString(nonce)
	if len(key) != ed25519.PrivateKeySize || err != nil || len(n) != 32 || base64.RawURLEncoding.EncodeToString(n) != nonce || len(raw) == 0 || len(raw) > 32<<10 {
		return "", ErrInvalid
	}
	body, _ := json.Marshal(objectBootGrant{1, nonce, objectBootDigest(raw), expires.Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(key, []byte("browser-storage-renewal/v1."+encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (g *ObjectBootGate) renewStorage(out http.ResponseWriter, r *http.Request, status ObjectBootStatus) {
	deny := func() { http.Error(out, `{"error":"denied"}`, http.StatusForbidden) }
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		deny()
		return
	}
	grant, err := verifyObjectGrant(g.issuer, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), status.Nonce, time.Now(), "browser-storage-renewal/v1.")
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
	var c ObjectStorageRenewal
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err != nil || grant.Digest != objectBootDigest(raw) || d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Version != 1 || c.BootDigest != status.Digest || c.Storage.Expires == 0 || !storageLeaseUsable(c.Storage, time.Now()) {
		deny()
		return
	}
	if _, err = newS3BlobBackend(c.Storage, "validation", "validation", nil); err != nil {
		deny()
		return
	}
	g.mu.Lock()
	if g.ctx.Err() != nil || r.Context().Err() != nil || grant.Expires <= time.Now().Unix() || g.status.State != "ready" || g.worker == nil || g.status.StorageState == "renewing" || g.status.StorageGeneration == ^uint64(0) || c.Generation != g.status.StorageGeneration+1 || c.Previous != g.status.StorageDigest || c.Storage.Expires <= g.status.StorageExpires {
		g.mu.Unlock()
		http.Error(out, `{"error":"renewal unavailable or claimed"}`, http.StatusConflict)
		return
	}
	g.status.StorageGeneration, g.status.StorageDigest, g.status.StorageState = c.Generation, grant.Digest, "renewing"
	status, worker := g.status, g.worker
	g.mu.Unlock()
	// A disconnect cannot undo a claim or authorize resending credentials.
	go g.applyStorageRenewal(worker, c)
	out.WriteHeader(http.StatusAccepted)
	json.NewEncoder(out).Encode(status)
}

func (g *ObjectBootGate) applyStorageRenewal(w *Worker, c ObjectStorageRenewal) {
	ctx, cancel := context.WithTimeout(g.lifetime, 2*time.Minute)
	defer cancel()
	err := g.renew(ctx, w, c.Storage)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.status.StorageState = "failed"
		return
	}
	g.status.StorageState, g.status.StorageExpires = "ready", c.Storage.Expires
	if g.status.State == "ready" {
		g.scheduleStorageExpiryLocked()
	}
}

func (g *ObjectBootGate) scheduleStorageExpiryLocked() {
	if g.storageTimer != nil {
		g.storageTimer.Stop()
	}
	expires := g.status.StorageExpires
	if expires != 0 {
		g.storageTimer = time.AfterFunc(time.Until(time.Unix(expires, 0).Add(-storageDrainLead)), func() {
			g.expireStorage(expires, time.Now())
		})
	}
}

func (g *ObjectBootGate) expireStorage(expires int64, now time.Time) {
	g.mu.Lock()
	// An old timer must not checkpoint a successfully renewed lease. Claim the
	// same drain state as the operator before allowing any new request through.
	if g.status.State != "ready" || g.status.StorageExpires != expires || now.Before(time.Unix(expires, 0).Add(-storageDrainLead)) {
		g.mu.Unlock()
		return
	}
	g.status.State, g.drainClaimed = "stopping", true
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	_ = g.Close(ctx)
}

// Replace only the backend after authenticating the existing fixed identity.
// Keep observed CAS versions and quarantine intact; reopening SealedStore would
// erase those guards and could conceal an ambiguous write.
func (s *SealedStore) renewS3Credentials(ctx context.Context, owner, audience string, c S3StoreConfig, testHTTP *http.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remote == nil || s.remote.owner != owner || s.remote.blocked || ctx.Err() != nil || c.Expires == 0 || !storageLeaseUsable(c, time.Now()) {
		return ErrDenied
	}
	previous, ok := s.remote.backend.(*s3BlobBackend)
	if !ok || previous.bucket != c.Bucket || previous.client.Options().Region != c.Region {
		return ErrDenied
	}
	next, err := newS3BlobBackend(c, owner, audience, testHTTP)
	if err != nil || next.prefix != previous.prefix {
		return ErrDenied
	}
	verified, err := newRemoteSealedStore(ctx, owner, audience, s.key[:], next, false)
	if err != nil {
		return ErrDenied
	}
	clear(verified.key[:])
	if ctx.Err() != nil {
		return ErrDenied
	}
	s.remote.backend = next
	return nil
}
