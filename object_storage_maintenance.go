package browser

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const storageRenewLead = 20 * time.Minute

func storageRenewDue(c S3StoreConfig, now time.Time) bool {
	return c.Expires == 0 || c.Expires <= now.Add(storageRenewLead).Unix()
}

func (c *ObjectController) refreshControlStorage(ctx context.Context) error {
	if c.issuer == nil || !storageRenewDue(c.storage, c.clock()) {
		return nil
	}
	storage, err := c.issuer.Issue(ctx, "system", c.audience)
	if err != nil || storage.Bucket != c.storage.Bucket || storage.Region != c.storage.Region || storage.SessionToken == "" || !storageLeaseUsable(storage, c.clock()) || storage.Expires <= c.clock().Add(2*storageRenewLead).Unix() || storage.Expires <= c.storage.Expires {
		return ErrUnavailable
	}
	if err = c.renew(ctx, storage); err != nil {
		return ErrUncertain
	}
	c.storage = storage
	return nil
}

// MaintainStorage handles existing infrastructure only. A pass is bounded to
// eight concurrent owners and 45 seconds each, without changing Fleet.LastUsed,
// acquiring agent leases, waking stopped workers or touching quarantined ones.
func (c *ObjectController) MaintainStorage(ctx context.Context) error {
	if c == nil || c.Control == nil || c.Control.Fleet == nil || c.provisioner == nil || c.clock == nil {
		return ErrInvalid
	}
	c.maintenanceMu.Lock()
	defer c.maintenanceMu.Unlock()
	if c.issuer == nil {
		return nil
	}
	if err := c.refreshControlStorage(ctx); err != nil {
		return err
	}
	fleet := c.Control.Fleet
	fleet.mu.Lock()
	instances := make([]Instance, 0, len(fleet.assignments))
	for _, a := range fleet.assignments {
		if a.State == "running" && (a.Users > 0 || c.clock().Sub(a.LastUsed) < c.idle) {
			instances = append(instances, a.Instance)
		}
	}
	fleet.mu.Unlock()
	var failed atomic.Bool
	var workers sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, instance := range instances {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			workers.Wait()
			return ctx.Err()
		}
		workers.Add(1)
		go func(i Instance) {
			defer workers.Done()
			defer func() { <-slots }()
			bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			if c.provisioner.MaintainStorage(bounded, i) != nil {
				failed.Store(true)
			}
		}(instance)
	}
	workers.Wait()
	if failed.Load() {
		return ErrUnavailable
	}
	return nil
}

func (p *ObjectProvisioner) issueStorage(ctx context.Context, i Instance) (S3StoreConfig, error) {
	if p.issuer == nil || ctx.Err() != nil {
		return S3StoreConfig{}, ErrDenied
	}
	storage, err := p.issuer.Issue(ctx, i.Owner, i.Name)
	if err != nil || p.validateReplacement(i.Owner, storage) != nil || storage.SessionToken == "" || !storageLeaseUsable(storage, p.clock()) || storage.Expires <= p.clock().Add(2*storageRenewLead).Unix() {
		return S3StoreConfig{}, ErrUnavailable
	}
	return storage, nil
}

func (p *ObjectProvisioner) freshPreparedStorage(ctx context.Context, record objectProvisionRecord) (objectProvisionRecord, error) {
	if p.issuer == nil || !storageRenewDue(record.currentStorage(), p.clock()) {
		return record, nil
	}
	storage, err := p.issueStorage(ctx, record.Instance)
	if err != nil {
		return record, err
	}
	return p.refreshPreparedStorage(ctx, record, storage)
}

// MaintainStorage renews only an existing running assignment. It does not wake,
// reprovision or reassign a worker. Retained uncertainty is inspected before any
// new credential is issued, so repeated maintenance never replays delivery.
func (p *ObjectProvisioner) MaintainStorage(ctx context.Context, i Instance) error {
	if p.issuer == nil {
		return nil
	}
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := p.load(ctx, i)
	if err != nil || record.State != "ready" || record.Boot == nil {
		return ErrDenied
	}
	if record.Renewal == nil && !storageRenewDue(record.currentStorage(), p.clock()) {
		return nil
	}
	if err = p.cloud(ctx, i, "running"); err != nil {
		return err
	}
	if _, err = p.reconcileStorage(ctx, &record); err != nil {
		return err
	}
	if !storageRenewDue(record.currentStorage(), p.clock()) {
		return nil
	}
	// Attest before using the issuer, including after an autonomous drain.
	status, err := p.operator(i).Inspect(ctx, *record.Boot)
	if err != nil || status.State != "ready" {
		return ErrUnavailable
	}
	storage, err := p.issueStorage(ctx, i)
	if err != nil {
		return err
	}
	return p.renewStorage(ctx, i, record, storage)
}
