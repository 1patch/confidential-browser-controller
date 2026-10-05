package browser

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"
)

// RenewStorageRecorded attests the existing boot, reserves the complete renewal
// commitment durably, then transmits once. On uncertainty use InspectStorage;
// never call this method again to resolve an existing reservation.
func (o ObjectBootOperator) RenewStorageRecorded(parent context.Context, receipt ObjectBootStatus, storage S3StoreConfig, reserve func(ObjectBootStatus) error) (ObjectBootStatus, error) {
	if len(o.Key) != ed25519.PrivateKeySize || reserve == nil || !validObjectBootStatus(receipt) || receipt.Digest == "" || storage.Expires == 0 || !storageLeaseUsable(storage, time.Now()) {
		return ObjectBootStatus{}, ErrInvalid
	}
	if _, err := newS3BlobBackend(storage, o.Target.Owner, o.Target.Audience, nil); err != nil {
		return ObjectBootStatus{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	client, err := o.client(ctx)
	if err != nil {
		return ObjectBootStatus{}, err
	}
	defer client.CloseIdleConnections()
	status, err := o.request(ctx, client, http.MethodGet, "", nil)
	if err != nil || status.Nonce != receipt.Nonce || status.Digest != receipt.Digest || status.State != "ready" || status.StorageState == "renewing" || status.StorageGeneration != receipt.StorageGeneration || status.StorageDigest != receipt.StorageDigest || status.StorageGeneration == ^uint64(0) || storage.Expires <= status.StorageExpires {
		return ObjectBootStatus{}, ErrUncertain
	}
	raw, _ := json.Marshal(ObjectStorageRenewal{Version: 1, BootDigest: status.Digest, Generation: status.StorageGeneration + 1, Previous: status.StorageDigest, Storage: storage})
	defer clear(raw)
	token, err := SignObjectStorageRenewal(o.Key, status.Nonce, raw, time.Now().Add(time.Minute))
	if err != nil {
		return ObjectBootStatus{}, err
	}
	status.StorageGeneration++
	status.StorageDigest, status.StorageState = objectBootDigest(raw), "renewing"
	if reserve(status) != nil {
		return status, ErrUncertain
	}
	accepted, err := o.requestPath(ctx, client, http.MethodPost, "/v1/storage", token, raw)
	if err != nil || accepted.Nonce != status.Nonce || accepted.Digest != status.Digest || accepted.StorageGeneration != status.StorageGeneration || accepted.StorageDigest != status.StorageDigest || accepted.StorageState != "renewing" {
		return status, ErrUncertain
	}
	return accepted, nil
}

// InspectStorage resolves only the exact retained generation. It never reads
// credentials, sends a POST or accepts a newer/different operator's renewal.
func (o ObjectBootOperator) InspectStorage(ctx context.Context, receipt ObjectBootStatus) (ObjectBootStatus, error) {
	if receipt.StorageGeneration == 0 || !validObjectBootStatus(receipt) {
		return ObjectBootStatus{}, ErrInvalid
	}
	status, err := o.Inspect(ctx, receipt)
	if err != nil || status.StorageGeneration != receipt.StorageGeneration || status.StorageDigest != receipt.StorageDigest {
		return ObjectBootStatus{}, ErrUncertain
	}
	return status, nil
}
