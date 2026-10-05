package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// ObjectBootOperator runs outside the public image. Its target comes from an
// operator's retained provisioning record, never an agent or endpoint redirect.
type ObjectBootOperator struct {
	Target  CredentialTarget
	Key     ed25519.PrivateKey
	connect func(string, string) (*http.Client, error) // same-package tests only
}

func (o ObjectBootOperator) client(ctx context.Context) (*http.Client, error) {
	t := o.Target
	if ctx.Err() != nil || !identifier.MatchString(t.Owner) || !identifier.MatchString(t.Audience) || !enclaveDomain.MatchString(t.Domain) || !strings.HasPrefix(t.Domain, t.Audience+".") || !releasePin.MatchString(t.Repository) {
		return nil, ErrDenied
	}
	connect := o.connect
	if connect == nil {
		connect = VerifiedHTTP
	}
	client, err := connect(t.Domain, t.Repository)
	if err != nil || client == nil || ctx.Err() != nil {
		return nil, ErrDenied
	}
	return client, nil
}

// Deliver attests before reading private input, then makes one POST. On an
// uncertain acknowledgment, retain the returned nonce/digest with Target and
// call Inspect; never call Deliver again to resolve that uncertainty.
func (o ObjectBootOperator) Deliver(parent context.Context, input io.Reader) (ObjectBootStatus, error) {
	return o.deliver(parent, input, nil)
}

// DeliverRecorded requires a durable reservation callback before the private
// POST. Operators must refuse an existing receipt and use Inspect after any
// uncertain outcome, including a crash immediately after this callback.
func (o ObjectBootOperator) DeliverRecorded(parent context.Context, input io.Reader, reserve func(ObjectBootStatus) error) (ObjectBootStatus, error) {
	if reserve == nil {
		return ObjectBootStatus{}, ErrInvalid
	}
	return o.deliver(parent, input, reserve)
}

// The fleet persists a receipt before the POST can begin. Manual callers of
// Deliver must instead retain the returned receipt themselves on uncertainty.
func (o ObjectBootOperator) deliver(parent context.Context, input io.Reader, reserve func(ObjectBootStatus) error) (ObjectBootStatus, error) {
	var zero ObjectBootStatus
	if len(o.Key) != ed25519.PrivateKeySize || input == nil {
		return zero, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	client, err := o.client(ctx)
	if err != nil {
		return zero, err
	}
	defer client.CloseIdleConnections()
	status, err := o.request(ctx, client, http.MethodGet, "", nil)
	if err != nil || status.State != "waiting" || status.Digest != "" {
		return zero, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(input, (64<<10)+1))
	defer clear(raw)
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 || ctx.Err() != nil {
		return zero, ErrInvalid
	}
	c, err := ParseObjectBootstrap(raw)
	issuer := base64.StdEncoding.EncodeToString(o.Key.Public().(ed25519.PublicKey))
	if err != nil || c.Browser.Owner != o.Target.Owner || c.Browser.Audience != o.Target.Audience || c.Browser.ExecutePublicKey == issuer || c.Browser.SecretsPublicKey == issuer {
		return zero, ErrDenied
	}
	c = ObjectBootstrap{}
	token, err := SignObjectBootstrap(o.Key, status.Nonce, raw, time.Now().Add(time.Minute))
	if err != nil {
		return zero, err
	}
	status.State, status.Digest = "starting", objectBootDigest(raw)
	if reserve != nil {
		if err := reserve(status); err != nil {
			return status, ErrUncertain
		}
	}
	accepted, err := o.request(ctx, client, http.MethodPost, token, raw)
	if err != nil || accepted.Nonce != status.Nonce || accepted.Digest != status.Digest || (accepted.State != "starting" && accepted.State != "ready") {
		return status, ErrUncertain
	}
	return accepted, nil
}

// Inspect is read-only and freshly attested. Both the process nonce and private
// body digest must still match the retained receipt. A replacement process or
// different bootstrap cannot be mistaken for successful recovery.
func (o ObjectBootOperator) Inspect(parent context.Context, receipt ObjectBootStatus) (ObjectBootStatus, error) {
	var zero ObjectBootStatus
	if !validObjectBootStatus(receipt) || receipt.Digest == "" {
		return zero, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	client, err := o.client(ctx)
	if err != nil {
		return zero, err
	}
	defer client.CloseIdleConnections()
	status, err := o.request(ctx, client, http.MethodGet, "", nil)
	if err != nil || status.Nonce != receipt.Nonce || status.Digest != receipt.Digest || status.StorageGeneration != receipt.StorageGeneration || status.StorageDigest != receipt.StorageDigest {
		return zero, ErrUncertain
	}
	return status, nil
}

// DrainRecorded sends at most one boot-bound checkpoint request. The caller
// reserves that intent durably first and uses Inspect after an uncertain reply.
// This never powers off a VM; a closed storage head must be checked separately.
func (o ObjectBootOperator) DrainRecorded(ctx context.Context, receipt ObjectBootStatus, reserve func(ObjectBootStatus) error) (ObjectBootStatus, error) {
	if len(o.Key) != ed25519.PrivateKeySize || reserve == nil || !validObjectBootStatus(receipt) || receipt.Digest == "" {
		return ObjectBootStatus{}, ErrInvalid
	}
	client, err := o.client(ctx)
	if err != nil {
		return ObjectBootStatus{}, err
	}
	defer client.CloseIdleConnections()
	status, err := o.request(ctx, client, http.MethodGet, "", nil)
	if err != nil || status.Nonce != receipt.Nonce || status.Digest != receipt.Digest || status.State != "ready" || status.StorageGeneration != receipt.StorageGeneration || status.StorageDigest != receipt.StorageDigest || status.StorageState == "renewing" {
		return ObjectBootStatus{}, ErrUncertain
	}
	token, err := SignObjectDrain(o.Key, status, time.Now().Add(time.Minute))
	if err != nil {
		return ObjectBootStatus{}, err
	}
	status.State = "stopping"
	if reserve(status) != nil {
		return status, ErrUncertain
	}
	accepted, err := o.requestPath(ctx, client, http.MethodPost, "/v1/drain", token, nil)
	if err != nil || accepted.Nonce != status.Nonce || accepted.Digest != status.Digest || accepted.State != "stopping" {
		return status, ErrUncertain
	}
	return accepted, nil
}

func validObjectBootStatus(s ObjectBootStatus) bool {
	if s.StorageExpires < 0 || s.StorageExpires > 253402300799 || (s.StorageGeneration == 0 && (s.StorageDigest != "" || s.StorageState != "")) {
		return false
	}
	if s.StorageGeneration > 0 && (!hexIdentifier(s.StorageDigest, 32) || (s.StorageState != "renewing" && s.StorageState != "ready" && s.StorageState != "failed")) {
		return false
	}
	if s.Failure != "" && (s.State != "failed" || !validStartupFailure(s.Failure)) {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(s.Nonce)
	if s.Version != 1 || err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != s.Nonce {
		return false
	}
	if s.State == "waiting" {
		return s.Digest == "" && s.StorageGeneration == 0 && s.StorageExpires == 0
	}
	switch s.State {
	case "starting", "ready", "failed", "stopping", "stopped":
		digest, err := hex.DecodeString(s.Digest)
		return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == s.Digest
	default:
		return false
	}
}

func (o ObjectBootOperator) request(ctx context.Context, client *http.Client, method, token string, body []byte) (ObjectBootStatus, error) {
	return o.requestPath(ctx, client, method, "/v1/bootstrap", token, body)
}

func (o ObjectBootOperator) requestPath(ctx context.Context, client *http.Client, method, path, token string, body []byte) (ObjectBootStatus, error) {
	var status ObjectBootStatus
	r, err := http.NewRequestWithContext(ctx, method, "https://"+o.Target.Domain+path, bytes.NewReader(body))
	if err != nil {
		return status, ErrInvalid
	}
	r.GetBody = nil // Do not give the transport a way to replay a bootstrap body.
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(r)
	if err != nil {
		return status, ErrUnavailable
	}
	defer resp.Body.Close()
	expected := http.StatusOK
	if method == http.MethodPost {
		expected = http.StatusAccepted
	}
	if resp.StatusCode != expected {
		return status, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2049))
	if err != nil || len(raw) > 2048 {
		return status, ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&status) != nil || d.Decode(new(any)) != io.EOF || !validObjectBootStatus(status) {
		return ObjectBootStatus{}, ErrDenied
	}
	return status, nil
}
