package browser

import (
	"context"
	"encoding/json"
	"time"
)

// The pending credentials and their exact attested commitment are encrypted in
// the same conditional write as the intent. A reopened record only inspects it.
type objectProvisionRenewal struct {
	Storage S3StoreConfig    `json:"storage"`
	Receipt ObjectBootStatus `json:"receipt"`
}

func (r objectProvisionRecord) currentStorage() S3StoreConfig {
	if r.Storage != nil {
		return *r.Storage
	}
	return r.Bootstrap.Storage
}

func (p *ObjectProvisioner) validateReplacement(owner string, storage S3StoreConfig) error {
	policy, ok := p.owners[owner]
	if !ok || storage.Bucket != policy.Storage.Bucket || storage.Region != policy.Storage.Region {
		return ErrDenied
	}
	if _, err := newS3BlobBackend(storage, owner, "validation", nil); err != nil {
		return ErrDenied
	}
	for other, config := range p.owners {
		if other != owner && config.Storage.AccessKeyID == storage.AccessKeyID {
			return ErrDenied
		}
	}
	return nil
}

func validateProvisionRenewal(r objectProvisionRecord) error {
	if r.Storage != nil && (r.Storage.Expires == 0 || r.Storage.SessionToken == "") {
		return ErrDenied
	}
	if r.State == "prepared" && r.Bootstrap.Storage != r.currentStorage() {
		return ErrDenied
	}
	if (r.State == "ready" || r.State == "draining") && (r.Boot == nil || r.Boot.StorageExpires != r.currentStorage().Expires) {
		return ErrDenied
	}
	if r.Renewal == nil {
		return nil
	}
	if r.State != "ready" || r.Boot == nil || !validObjectBootStatus(r.Renewal.Receipt) {
		return ErrDenied
	}
	pending, previous := r.Renewal, *r.Boot
	status := pending.Receipt
	if status.State != "ready" || status.StorageState != "renewing" || status.Nonce != previous.Nonce || status.Digest != previous.Digest || previous.StorageGeneration == ^uint64(0) || status.StorageGeneration != previous.StorageGeneration+1 || status.StorageExpires != previous.StorageExpires || pending.Storage.Expires <= previous.StorageExpires || pending.Storage.SessionToken == "" || pending.Storage.Bucket != r.Bootstrap.Storage.Bucket || pending.Storage.Region != r.Bootstrap.Storage.Region {
		return ErrDenied
	}
	if _, err := newS3BlobBackend(pending.Storage, r.Instance.Owner, r.Instance.Name, nil); err != nil {
		return ErrDenied
	}
	raw, _ := json.Marshal(ObjectStorageRenewal{Version: 1, BootDigest: previous.Digest, Generation: status.StorageGeneration, Previous: previous.StorageDigest, Storage: pending.Storage})
	defer clear(raw)
	if objectBootDigest(raw) != status.StorageDigest {
		return ErrDenied
	}
	return nil
}

// RenewStorage is a trusted issuer/controller operation, never an agent route.
// It preserves the original bootstrap commitment, key and policy. The caller
// provides independently issued owner-scoped credentials; this method does not
// acquire IAM authority or schedule issuance.
func (p *ObjectProvisioner) RenewStorage(ctx context.Context, i Instance, storage S3StoreConfig) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "running"); err != nil {
		return err
	}
	record, err := p.load(ctx, i)
	if err != nil {
		return err
	}
	return p.renewStorage(ctx, i, record, storage)
}

// Caller holds the owner/instance lock and has verified the running cloud VM.
func (p *ObjectProvisioner) renewStorage(ctx context.Context, i Instance, record objectProvisionRecord, storage S3StoreConfig) error {
	if record.State != "ready" || record.Boot == nil || p.validateReplacement(i.Owner, storage) != nil {
		return ErrDenied
	}
	var err error
	if record.Renewal != nil {
		// A caller cannot substitute a fresh credential set for an unresolved
		// intent. ReconcileStorage can inspect it without possessing the input.
		if storage != record.Renewal.Storage {
			return ErrUncertain
		}
	} else {
		if storage == record.currentStorage() && record.Storage != nil {
			status, err := p.operator(i).Inspect(ctx, *record.Boot)
			if err != nil || status.State != "ready" || status.StorageState == "renewing" || status.StorageExpires != storage.Expires {
				return ErrUncertain
			}
			return nil
		}
		if storage.Expires == 0 || !storageLeaseUsable(storage, time.Now()) || storage.Expires <= record.Boot.StorageExpires {
			return ErrDenied
		}
		_, err = p.operator(i).RenewStorageRecorded(ctx, *record.Boot, storage, func(receipt ObjectBootStatus) error {
			pending := record
			pending.Renewal = &objectProvisionRenewal{Storage: storage, Receipt: receipt}
			if err := validateProvisionRenewal(pending); err != nil {
				return err
			}
			if err := p.save(ctx, pending, false); err != nil {
				return err
			}
			record = pending
			return nil
		})
		if err != nil && record.Renewal == nil {
			return err
		}
	}
	state, err := p.reconcileStorage(ctx, &record)
	if err == nil && state == "failed" {
		return ErrDenied
	}
	return err
}

// ReconcileStorage performs no POST and issues no credential. Missing delivery,
// another generation, a restarted worker or ambiguous storage writes stay closed.
func (p *ObjectProvisioner) ReconcileStorage(ctx context.Context, i Instance) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "running"); err != nil {
		return err
	}
	record, err := p.load(ctx, i)
	if err != nil || record.State != "ready" || record.Boot == nil {
		return ErrDenied
	}
	if record.Renewal == nil {
		status, err := p.operator(i).Inspect(ctx, *record.Boot)
		if err != nil || (status.State != "ready" && status.State != "stopping" && status.State != "stopped") || status.StorageExpires != record.currentStorage().Expires || status.StorageState == "renewing" {
			return ErrUncertain
		}
		if status.StorageState == "failed" {
			return ErrDenied
		}
		return nil
	}
	state, err := p.reconcileStorage(ctx, &record)
	if err == nil && state == "failed" {
		return ErrDenied
	}
	return err
}

func (p *ObjectProvisioner) reconcileStorage(parent context.Context, record *objectProvisionRecord) (string, error) {
	if record.Renewal == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	for {
		status, err := p.operator(record.Instance).InspectStorage(ctx, record.Renewal.Receipt)
		if err != nil || (status.State != "ready" && status.State != "stopping" && status.State != "stopped") {
			return "", ErrUncertain
		}
		if status.StorageState == "ready" || status.StorageState == "failed" {
			next := *record
			if status.StorageState == "ready" {
				if status.StorageExpires != record.Renewal.Storage.Expires {
					return "", ErrUncertain
				}
				storage := record.Renewal.Storage
				next.Storage = &storage
			} else if status.StorageExpires != record.Boot.StorageExpires {
				return "", ErrUncertain
			}
			next.Boot, next.Renewal = &status, nil
			if err := p.save(ctx, next, false); err != nil {
				return "", ErrUncertain
			}
			*record = next
			return status.StorageState, nil
		}
		if status.StorageState != "renewing" {
			return "", ErrUncertain
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ErrUncertain
		case <-timer.C:
		}
	}
}

// RefreshStoppedStorage authenticates the existing closed profile with a new
// lease before saving it for the next boot. It never initializes missing state,
// replaces the encryption key, powers on a VM or resets a quarantined profile.
func (p *ObjectProvisioner) RefreshStoppedStorage(ctx context.Context, i Instance, storage S3StoreConfig) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "stopped"); err != nil {
		return err
	}
	record, err := p.load(ctx, i)
	if err != nil {
		return err
	}
	_, err = p.refreshPreparedStorage(ctx, record, storage)
	return err
}

func (p *ObjectProvisioner) refreshPreparedStorage(ctx context.Context, record objectProvisionRecord, storage S3StoreConfig) (objectProvisionRecord, error) {
	if record.State != "prepared" || record.Boot != nil || record.Renewal != nil || p.validateReplacement(record.Instance.Owner, storage) != nil || storage.Expires == 0 || !storageLeaseUsable(storage, time.Now()) {
		return record, ErrDenied
	}
	if storage == record.currentStorage() {
		return record, p.closedProfile(ctx, record)
	}
	if storage.Expires <= record.currentStorage().Expires {
		return record, ErrDenied
	}
	record.Storage = &storage
	record.Bootstrap.Storage = storage
	if err := p.closedProfile(ctx, record); err != nil {
		return record, err
	}
	return record, p.save(ctx, record, false)
}
