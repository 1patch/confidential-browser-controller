package browser

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"time"
)

// ControllerBootOperator retains the same exact-host attested transport and
// immutable reservation boundary as worker delivery, with a different signing
// purpose, endpoint and input schema. The target owner must be system.
type ControllerBootOperator struct {
	Target  CredentialTarget
	Key     ed25519.PrivateKey
	connect func(string, string) (*http.Client, error)
}

func validControllerBootStatus(s ObjectBootStatus) bool {
	return validObjectBootStatus(s) && s.StorageGeneration == 0 && s.StorageDigest == "" && s.StorageState == "" && s.StorageExpires == 0 && s.Failure == "" && (s.State == "waiting" || s.State == "starting" || s.State == "ready" || s.State == "failed")
}

func (o ControllerBootOperator) transport() ObjectBootOperator {
	return ObjectBootOperator{Target: o.Target, Key: o.Key, connect: o.connect}
}

func (o ControllerBootOperator) DeliverRecorded(parent context.Context, input io.Reader, reserve func(ObjectBootStatus) error) (ObjectBootStatus, error) {
	var zero ObjectBootStatus
	if o.Target.Owner != "system" || len(o.Key) != ed25519.PrivateKeySize || input == nil || reserve == nil {
		return zero, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	transport := o.transport()
	client, err := transport.client(ctx)
	if err != nil {
		return zero, err
	}
	defer client.CloseIdleConnections()
	status, err := transport.requestPath(ctx, client, http.MethodGet, controllerBootPath, "", nil)
	if err != nil || !validControllerBootStatus(status) || status.State != "waiting" {
		return zero, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(input, (32<<10)+1))
	defer clear(raw)
	if err != nil || len(raw) == 0 || len(raw) > 32<<10 || ctx.Err() != nil {
		return zero, ErrInvalid
	}
	location, err := ParseObjectControllerLocation(raw)
	if err != nil || location.Audience != o.Target.Audience || !storageLeaseUsable(location.Storage, time.Now()) {
		return zero, ErrDenied
	}
	location = ObjectControllerLocation{}
	token, err := SignControllerBootstrap(o.Key, status.Nonce, raw, time.Now().Add(time.Minute))
	if err != nil {
		return zero, err
	}
	status.State, status.Digest = "starting", objectBootDigest(raw)
	if reserve(status) != nil {
		return status, ErrUncertain
	}
	accepted, err := transport.requestPath(ctx, client, http.MethodPost, controllerBootPath, token, raw)
	if err != nil || !validControllerBootStatus(accepted) || accepted.Nonce != status.Nonce || accepted.Digest != status.Digest || (accepted.State != "starting" && accepted.State != "ready") {
		return status, ErrUncertain
	}
	return accepted, nil
}

func (o ControllerBootOperator) Inspect(parent context.Context, receipt ObjectBootStatus) (ObjectBootStatus, error) {
	var zero ObjectBootStatus
	if o.Target.Owner != "system" || !validControllerBootStatus(receipt) || receipt.Digest == "" {
		return zero, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	transport := o.transport()
	client, err := transport.client(ctx)
	if err != nil {
		return zero, err
	}
	defer client.CloseIdleConnections()
	status, err := transport.requestPath(ctx, client, http.MethodGet, controllerBootPath, "", nil)
	if err != nil || !validControllerBootStatus(status) || status.Nonce != receipt.Nonce || status.Digest != receipt.Digest {
		return zero, ErrUncertain
	}
	return status, nil
}
