package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ObjectOwnerPolicy is trusted operator input. S3 buckets/credentials must be
// provisioned and IAM-tested independently per owner before fleet enrollment.
// This component never creates cloud IAM resources or treats shared credentials
// as a tenant boundary. Temporary credentials must outlive graceful shutdown.
type ObjectOwnerPolicy struct {
	Browser Bootstrap     `json:"browser"`
	Storage S3StoreConfig `json:"storage"`
}

type objectProvisionRecord struct {
	Version    int                     `json:"version"`
	Instance   Instance                `json:"instance"`
	PolicyHash string                  `json:"policyHash"`
	State      string                  `json:"state"`
	Bootstrap  ObjectBootstrap         `json:"bootstrap"`
	Boot       *ObjectBootStatus       `json:"boot,omitempty"`
	LastNonce  string                  `json:"lastNonce,omitempty"`
	Storage    *S3StoreConfig          `json:"storage,omitempty"`
	Renewal    *objectProvisionRenewal `json:"renewal,omitempty"`
}

// ObjectProvisioner uses the controller's encrypted system store. It provisions
// an immutable owner/key/profile binding once, and records boot delivery before
// sending any secret. Per-owner locks allow independent cold starts in parallel.
// Store must have a single controller writer (the controller directory lock).
type ObjectProvisioner struct {
	provider *TinfoilProvider
	store    *SealedStore
	key      ed25519.PrivateKey
	owners   map[string]ObjectOwnerPolicy
	locks    map[string]*sync.Mutex
	mu       sync.Mutex
	names    map[string]*sync.Mutex
	open     func(context.Context, ObjectBootstrap, bool) (*SealedStore, error)
	connect  func(string, string) (*http.Client, error) // same-package tests only
	issuer   StorageLeaseIssuer
	clock    func() time.Time
}

func NewObjectProvisioner(provider *TinfoilProvider, store *SealedStore, key ed25519.PrivateKey, owners map[string]ObjectOwnerPolicy, issuers ...StorageLeaseIssuer) (*ObjectProvisioner, error) {
	if provider == nil || store == nil || len(key) != ed25519.PrivateKeySize || !releasePin.MatchString(provider.Repository) || !enclaveDomain.MatchString("browser-test."+provider.DomainSuffix) || len(owners) < 1 || len(owners) > 100 {
		return nil, ErrInvalid
	}
	if len(issuers) > 1 || len(issuers) == 1 && issuers[0] == nil {
		return nil, ErrInvalid
	}
	issuer := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	p := &ObjectProvisioner{provider: provider, store: store, key: append(ed25519.PrivateKey(nil), key...), owners: map[string]ObjectOwnerPolicy{}, locks: map[string]*sync.Mutex{}, names: map[string]*sync.Mutex{}}
	p.clock = time.Now
	if len(issuers) == 1 {
		p.issuer = issuers[0]
	}
	buckets, credentials := map[string]bool{}, map[string]bool{}
	for owner, config := range owners {
		if !identifier.MatchString(owner) || config.Browser.Owner != owner || config.Browser.Audience != "" || config.Browser.StorageKey != "" || config.Browser.InferenceKey != "" || config.Browser.ExecutePublicKey == issuer || config.Browser.SecretsPublicKey == issuer || buckets[config.Storage.Bucket] || credentials[config.Storage.AccessKeyID] {
			return nil, ErrDenied
		}
		// Clone policy slices: later mutation of caller-owned config cannot
		// silently change an existing owner's authority or cloud credentials.
		raw, _ := json.Marshal(config)
		json.Unmarshal(raw, &config)
		clear(raw)
		validation := ObjectBootstrap{Browser: config.Browser, Storage: config.Storage}
		validation.Browser.Audience = "validation"
		validation.Browser.StorageKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		raw, _ = json.Marshal(validation)
		_, err := ParseObjectBootstrap(raw)
		clear(raw)
		if err != nil {
			return nil, ErrDenied
		}
		buckets[config.Storage.Bucket], credentials[config.Storage.AccessKeyID] = true, true
		p.owners[owner], p.locks[owner] = config, &sync.Mutex{}
	}
	p.open = func(ctx context.Context, c ObjectBootstrap, create bool) (*SealedStore, error) {
		key, _ := base64.StdEncoding.DecodeString(c.Browser.StorageKey)
		defer clear(key)
		return NewS3SealedStore(ctx, c.Storage, c.Browser.Owner, c.Browser.Audience, key, create)
	}
	return p, nil
}

func (p *ObjectProvisioner) lock(i Instance) (func(), error) {
	lock, ok := p.locks[i.Owner]
	if !ok || !instanceID.MatchString(i.ID) || !identifier.MatchString(i.Name) || i.Repository != p.provider.Repository || i.Domain != i.Name+"."+p.provider.DomainSuffix {
		return nil, ErrDenied
	}
	lock.Lock()
	p.mu.Lock()
	nameLock := p.names[i.Name]
	if nameLock == nil {
		if len(p.names) >= 100 {
			p.mu.Unlock()
			lock.Unlock()
			return nil, ErrCapacity
		}
		nameLock = &sync.Mutex{}
		p.names[i.Name] = nameLock
	}
	p.mu.Unlock()
	nameLock.Lock()
	return func() {
		p.store.releaseRead("system", "object-provision", i.Name)
		nameLock.Unlock()
		lock.Unlock()
	}, nil
}

func (p *ObjectProvisioner) cloud(ctx context.Context, i Instance, state string) error {
	v, err := p.provider.get(ctx, i, true)
	if err != nil || v.Status != state || len(v.Volumes) != 0 || len(v.VolumeSlots) != 0 {
		return ErrDenied
	}
	return nil
}

func (p *ObjectProvisioner) policyHash(owner string) string {
	raw, _ := json.Marshal(p.owners[owner])
	defer clear(raw)
	return objectBootDigest(raw)
}

func (p *ObjectProvisioner) load(ctx context.Context, i Instance) (objectProvisionRecord, error) {
	var record objectProvisionRecord
	raw, err := p.store.GetContext(ctx, "system", "object-provision", i.Name)
	defer clear(raw)
	if err != nil {
		return record, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || record.Version != 1 || record.Instance != i || record.PolicyHash != p.policyHash(i.Owner) || record.Bootstrap.Browser.Owner != i.Owner || record.Bootstrap.Browser.Audience != i.Name {
		return objectProvisionRecord{}, ErrDenied
	}
	data, _ := json.Marshal(record.Bootstrap)
	_, err = ParseObjectBootstrap(data)
	digest := objectBootDigest(data)
	expected := p.owners[i.Owner]
	expected.Browser.Audience, expected.Browser.StorageKey = i.Name, record.Bootstrap.Browser.StorageKey
	// Browser policy and storage location never change. Once a renewal has
	// committed, authentication can differ from the original enrollment. The
	// bootstrap remains the exact body used for this boot until it checkpoints.
	if record.Storage != nil {
		if p.validateReplacement(i.Owner, *record.Storage) != nil || p.validateReplacement(i.Owner, record.Bootstrap.Storage) != nil {
			return objectProvisionRecord{}, ErrDenied
		}
		expected.Storage = record.Bootstrap.Storage
	}
	policy, _ := json.Marshal(ObjectBootstrap{Browser: expected.Browser, Storage: expected.Storage})
	if !bytes.Equal(policy, data) {
		err = ErrDenied
	}
	clear(policy)
	clear(data)
	if err != nil {
		return objectProvisionRecord{}, ErrDenied
	}
	if record.LastNonce != "" {
		nonce, err := base64.RawURLEncoding.DecodeString(record.LastNonce)
		if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != record.LastNonce {
			return objectProvisionRecord{}, ErrDenied
		}
	}
	switch record.State {
	case "preparing", "prepared":
		if record.Boot != nil {
			return objectProvisionRecord{}, ErrDenied
		}
	case "sending", "ready", "draining":
		if record.Boot == nil || !validObjectBootStatus(*record.Boot) || record.Boot.Digest != digest || record.Boot.Nonce == record.LastNonce {
			return objectProvisionRecord{}, ErrDenied
		}
	default:
		return objectProvisionRecord{}, ErrDenied
	}
	if err := validateProvisionRenewal(record); err != nil {
		return objectProvisionRecord{}, err
	}
	return record, nil
}

func (p *ObjectProvisioner) save(ctx context.Context, record objectProvisionRecord, create bool) error {
	raw, _ := json.Marshal(record)
	defer clear(raw)
	if create {
		return p.store.CreateContext(ctx, "system", "object-provision", record.Instance.Name, raw)
	}
	return p.store.PutContext(ctx, "system", "object-provision", record.Instance.Name, raw)
}

// Prepare is called only on an authoritatively stopped VM. Missing controller
// records create fresh keys once; incomplete records never become a new owner.
func (p *ObjectProvisioner) Prepare(ctx context.Context, i Instance) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "stopped"); err != nil {
		return err
	}
	return p.prepare(ctx, i)
}

func (p *ObjectProvisioner) prepare(ctx context.Context, i Instance) error {
	record, err := p.load(ctx, i)
	if errors.Is(err, os.ErrNotExist) {
		config := p.owners[i.Owner]
		if p.issuer != nil {
			config.Storage, err = p.issueStorage(ctx, i)
			if err != nil {
				return err
			}
		}
		var key [32]byte
		if _, err = rand.Read(key[:]); err != nil {
			return ErrUnavailable
		}
		config.Browser.Audience = i.Name
		config.Browser.StorageKey = base64.StdEncoding.EncodeToString(key[:])
		clear(key[:])
		record = objectProvisionRecord{Version: 1, Instance: i, PolicyHash: p.policyHash(i.Owner), State: "preparing", Bootstrap: ObjectBootstrap{Browser: config.Browser, Storage: config.Storage}}
		if p.issuer != nil {
			storage := config.Storage
			record.Storage = &storage
		}
		if err = p.save(ctx, record, true); err != nil {
			return ErrUncertain
		}
		store, err := p.open(ctx, record.Bootstrap, true)
		if err != nil || ProvisionProfile(ctx, store, i.Owner) != nil {
			return ErrUncertain
		}
		record.State = "prepared"
		return p.save(ctx, record, false)
	}
	if err != nil {
		return err
	}
	if record.State != "prepared" {
		return ErrUncertain
	}
	if record, err = p.freshPreparedStorage(ctx, record); err != nil {
		return err
	}
	return p.closedProfile(ctx, record)
}

func (p *ObjectProvisioner) closedProfile(ctx context.Context, record objectProvisionRecord) error {
	config := record.Bootstrap
	config.Storage = record.currentStorage()
	store, err := p.open(ctx, config, false)
	if err != nil {
		return ErrUncertain
	}
	raw, err := store.GetContext(ctx, record.Instance.Owner, "profile", "head")
	defer store.releaseRead(record.Instance.Owner, "profile", "head")
	if err != nil {
		return ErrUncertain
	}
	head, err := decodeProfileState(raw)
	clear(raw)
	if err != nil || head.State != "closed" {
		return ErrUncertain
	}
	return nil
}

func (p *ObjectProvisioner) operator(i Instance) ObjectBootOperator {
	return ObjectBootOperator{Target: CredentialTarget{Owner: i.Owner, Audience: i.Name, Domain: i.Domain, Repository: i.Repository}, Key: p.key, connect: p.connect}
}

func (p *ObjectProvisioner) activate(ctx context.Context, i Instance) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "running"); err != nil {
		return err
	}
	record, err := p.load(ctx, i)
	if errors.Is(err, os.ErrNotExist) {
		// Some create operations start a secretless VM immediately. Initialize
		// storage before any private bootstrap is delivered to that process.
		if err = p.prepare(ctx, i); err != nil {
			return err
		}
		record, err = p.load(ctx, i)
	}
	if err != nil {
		return err
	}
	operator := p.operator(i)
	if record.State == "prepared" {
		if record, err = p.freshPreparedStorage(ctx, record); err != nil {
			return err
		}
		if err = p.closedProfile(ctx, record); err != nil {
			return err
		}
		raw, _ := json.Marshal(record.Bootstrap)
		_, err = operator.deliver(ctx, bytes.NewReader(raw), func(receipt ObjectBootStatus) error {
			if receipt.Nonce == record.LastNonce {
				return ErrDenied
			}
			if err := p.cloud(ctx, i, "running"); err != nil {
				return err
			}
			pending := record
			pending.State, pending.Boot = "sending", &receipt
			if err := p.save(ctx, pending, false); err != nil {
				return err
			}
			record = pending
			return nil
		})
		clear(raw)
		if err != nil && (record.State != "sending" || record.Boot == nil) {
			return err
		}
	}
	if record.State != "sending" && record.State != "ready" {
		return ErrUncertain
	}
	if _, err = p.reconcileStorage(ctx, &record); err != nil {
		return err
	}
	// Lost POST acknowledgments and repeated Start calls only inspect the
	// retained receipt. They never submit a second bootstrap body.
	waiting, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	for {
		status, err := operator.Inspect(waiting, *record.Boot)
		if err != nil {
			return ErrUncertain
		}
		if status.State == "ready" {
			record.State, record.Boot = "ready", &status
			return p.save(ctx, record, false)
		}
		if status.State != "starting" {
			return ErrUncertain
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-waiting.Done():
			timer.Stop()
			return ErrUncertain
		case <-timer.C:
		}
	}
}

func (p *ObjectProvisioner) verifyBoot(ctx context.Context, i Instance) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := p.load(ctx, i)
	if err != nil || record.State != "ready" || record.Boot == nil {
		return ErrDenied
	}
	if _, err = p.reconcileStorage(ctx, &record); err != nil {
		return err
	}
	status, err := p.operator(i).Inspect(ctx, *record.Boot)
	if err != nil || status.State != "ready" {
		return ErrDenied
	}
	return nil
}

func (p *ObjectProvisioner) checkpointed(ctx context.Context, i Instance) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "stopped"); err != nil {
		return err
	}
	record, err := p.load(ctx, i)
	if err != nil || record.State == "preparing" || record.Renewal != nil {
		return ErrUncertain
	}
	if err = p.closedProfile(ctx, record); err != nil {
		return err
	}
	if record.Boot != nil {
		record.LastNonce = record.Boot.Nonce
	}
	record.State, record.Boot = "prepared", nil
	record.Bootstrap.Storage = record.currentStorage()
	return p.save(ctx, record, false)
}

// Cloud stop is not a graceful application shutdown on every provider. Finish
// the attested checkpoint while the VM and its network are still available.
func (p *ObjectProvisioner) drain(ctx context.Context, i Instance) error {
	unlock, err := p.lock(i)
	if err != nil {
		return err
	}
	defer unlock()
	if err = p.cloud(ctx, i, "running"); err != nil {
		return err
	}
	record, err := p.load(ctx, i)
	if err != nil || record.Boot == nil || (record.State != "ready" && record.State != "draining") {
		return ErrUncertain
	}
	if _, err = p.reconcileStorage(ctx, &record); err != nil {
		return err
	}
	operator := p.operator(i)
	if record.State == "ready" {
		status, inspectErr := operator.Inspect(ctx, *record.Boot)
		if inspectErr != nil {
			return ErrUncertain
		}
		// The worker can checkpoint itself before lease expiry. Authenticate
		// that transition and retain it before confirming cloud power-off.
		if status.State == "stopping" || status.State == "stopped" {
			record.State, record.Boot = "draining", &status
			if err = p.save(ctx, record, false); err != nil {
				return err
			}
		} else if status.State != "ready" {
			return ErrUncertain
		}
	}
	if record.State == "ready" {
		_, err = operator.DrainRecorded(ctx, *record.Boot, func(status ObjectBootStatus) error {
			pending := record
			pending.State, pending.Boot = "draining", &status
			if err := p.save(ctx, pending, false); err != nil {
				return err
			}
			record = pending
			return nil
		})
		if err != nil && record.State != "draining" {
			return err
		}
	}
	// A lost drain acknowledgment is only inspected; a still-ready worker is
	// uncertain, not permission to resend an unacknowledged intent.
	for {
		status, err := operator.Inspect(ctx, *record.Boot)
		if err != nil {
			return ErrUncertain
		}
		if status.State == "stopped" {
			return p.closedProfile(ctx, record)
		}
		if status.State != "stopping" {
			return ErrUncertain
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrUncertain
		case <-timer.C:
		}
	}
}
