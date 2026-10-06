package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ObjectControllerLocation is small enough for private bootstrap delivery. The
// potentially large 100-owner enrollment lives in an authenticated encrypted S3
// object, rather than exceeding Linux's per-environment-variable size limit.
// This location itself contains secrets and must arrive over attested transport.
type ObjectControllerLocation struct {
	Version    int           `json:"version"`
	Audience   string        `json:"audience"`
	StorageKey string        `json:"storageKey"`
	Storage    S3StoreConfig `json:"storage"`
	Digest     string        `json:"digest"`
}

type ObjectControllerConfig struct {
	Version             int                          `json:"version"`
	Audience            string                       `json:"audience"`
	ExecutePublicKey    string                       `json:"executePublicKey"`
	WorkerPrivateKey    string                       `json:"workerPrivateKey"`
	BootstrapPrivateKey string                       `json:"bootstrapPrivateKey"`
	AdminKey            string                       `json:"adminKey"`
	WorkerRepository    string                       `json:"workerRepository"`
	DomainSuffix        string                       `json:"domainSuffix"`
	Owners              map[string]ObjectOwnerPolicy `json:"owners"`
	Capacity            int                          `json:"capacity"`
	IdleMinutes         int                          `json:"idleMinutes"`
	StorageIssuer       *StorageIssuerConfig         `json:"storageIssuer,omitempty"`
	AgentRuntime        bool                         `json:"agentRuntime,omitempty"`
}

func ParseObjectControllerLocation(raw []byte) (ObjectControllerLocation, error) {
	var c ObjectControllerLocation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 32<<10 || d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Version != 1 || !identifier.MatchString(c.Audience) || !hexIdentifier(c.Digest, 32) {
		return ObjectControllerLocation{}, ErrInvalid
	}
	key, err := base64.StdEncoding.DecodeString(c.StorageKey)
	defer clear(key)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != c.StorageKey {
		return ObjectControllerLocation{}, ErrInvalid
	}
	if _, err = newS3BlobBackend(c.Storage, "system", c.Audience, nil); err != nil {
		return ObjectControllerLocation{}, ErrInvalid
	}
	return c, nil
}

func ParseObjectControllerConfig(raw []byte) (ObjectControllerConfig, error) {
	var c ObjectControllerConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1<<20 || d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Version != 1 || !identifier.MatchString(c.Audience) || !strings.HasPrefix(c.AdminKey, "admin_") || len(c.AdminKey) > 4096 || strings.ContainsAny(c.AdminKey, " \t\r\n") || c.Capacity < 1 || c.Capacity > 100 || c.IdleMinutes < 1 || c.IdleMinutes > 60 || c.WorkerPrivateKey == c.BootstrapPrivateKey {
		return ObjectControllerConfig{}, ErrInvalid
	}
	keys := make([][]byte, 0, 3)
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for _, encoded := range []string{c.ExecutePublicKey, c.WorkerPrivateKey, c.BootstrapPrivateKey} {
		key, err := base64.StdEncoding.DecodeString(encoded)
		keys = append(keys, key)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
			return ObjectControllerConfig{}, ErrInvalid
		}
	}
	worker := ed25519.NewKeyFromSeed(keys[1])
	issuer := ed25519.NewKeyFromSeed(keys[2])
	defer clear(worker)
	defer clear(issuer)
	workerPublic := base64.StdEncoding.EncodeToString(worker.Public().(ed25519.PublicKey))
	issuerPublic := base64.StdEncoding.EncodeToString(issuer.Public().(ed25519.PublicKey))
	if c.ExecutePublicKey == workerPublic || c.ExecutePublicKey == issuerPublic {
		return ObjectControllerConfig{}, ErrDenied
	}
	for owner, policy := range c.Owners {
		if owner == "system" || policy.Browser.ExecutePublicKey != workerPublic || policy.Browser.SecretsPublicKey == c.ExecutePublicKey {
			return ObjectControllerConfig{}, ErrDenied
		}
	}
	// Construction validates and copies policy; it performs no cloud operation.
	provider := &TinfoilProvider{AdminKey: c.AdminKey, Repository: c.WorkerRepository, DomainSuffix: c.DomainSuffix}
	provisioner, err := newObjectProvisioner(provider, &SealedStore{}, issuer, c.Owners, c.AgentRuntime)
	if err != nil {
		return ObjectControllerConfig{}, ErrDenied
	}
	clear(provisioner.key)
	if c.StorageIssuer != nil {
		if _, err := NewAWSStorageIssuer(*c.StorageIssuer); err != nil || len(c.StorageIssuer.Roles) != len(c.Owners)+1 {
			return ObjectControllerConfig{}, ErrDenied
		}
		if _, ok := c.StorageIssuer.Roles["system"]; !ok {
			return ObjectControllerConfig{}, ErrDenied
		}
		for owner, policy := range c.Owners {
			role, ok := c.StorageIssuer.Roles[owner]
			if !ok || role.Bucket != policy.Storage.Bucket || role.Region != policy.Storage.Region || policy.Storage.AccessKeyID == c.StorageIssuer.Authority.AccessKeyID {
				return ObjectControllerConfig{}, ErrDenied
			}
		}
	}
	return c, nil
}

func openObjectControllerStore(ctx context.Context, c ObjectControllerLocation, initialize bool) (*SealedStore, error) {
	key, _ := base64.StdEncoding.DecodeString(c.StorageKey)
	defer clear(key)
	return NewS3SealedStore(ctx, c.Storage, "system", c.Audience, key, initialize)
}

func validateObjectControllerBinding(location ObjectControllerLocation, config ObjectControllerConfig) error {
	if config.Audience != location.Audience || config.WorkerPrivateKey == location.StorageKey || config.BootstrapPrivateKey == location.StorageKey {
		return ErrDenied
	}
	for _, owner := range config.Owners {
		if owner.Storage.Bucket == location.Storage.Bucket || owner.Storage.AccessKeyID == location.Storage.AccessKeyID {
			return ErrDenied
		}
	}
	if config.StorageIssuer != nil {
		role := config.StorageIssuer.Roles["system"]
		if role.Bucket != location.Storage.Bucket || role.Region != location.Storage.Region || config.StorageIssuer.Authority.AccessKeyID == location.Storage.AccessKeyID {
			return ErrDenied
		}
	}
	return nil
}

// ProvisionObjectController is explicitly operator-only initialization. The
// location digest must match the canonical JSON encoding of config. This writes
// one immutable encrypted enrollment; it never changes an existing enrollment.
func ProvisionObjectController(ctx context.Context, location ObjectControllerLocation, config ObjectControllerConfig) error {
	return provisionObjectController(ctx, location, config, openObjectControllerStore)
}

func provisionObjectController(ctx context.Context, location ObjectControllerLocation, config ObjectControllerConfig, open func(context.Context, ObjectControllerLocation, bool) (*SealedStore, error)) error {
	raw, _ := json.Marshal(location)
	_, err := ParseObjectControllerLocation(raw)
	clear(raw)
	if err != nil {
		return err
	}
	raw, _ = json.Marshal(config)
	defer clear(raw)
	parsed, err := ParseObjectControllerConfig(raw)
	if err != nil || validateObjectControllerBinding(location, parsed) != nil || objectBootDigest(raw) != location.Digest {
		return ErrDenied
	}
	store, err := open(ctx, location, true)
	if err != nil {
		return err
	}
	defer store.releaseRead("system", "controller", "bootstrap")
	existing, err := store.GetContext(ctx, "system", "controller", "bootstrap")
	defer clear(existing)
	if err == nil {
		if !bytes.Equal(raw, existing) {
			return ErrDenied
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrUncertain
	}
	return store.CreateContext(ctx, "system", "controller", "bootstrap", raw)
}

type ObjectController struct {
	Control       *Control
	idle          time.Duration
	provisioner   *ObjectProvisioner
	issuer        StorageLeaseIssuer
	storage       S3StoreConfig
	audience      string
	clock         func() time.Time
	maintenanceMu sync.Mutex
	renew         func(context.Context, S3StoreConfig) error
}

// NewObjectController requires an existing encrypted identity and enrollment.
// Starting a service never provisions empty state or replaces a missing key.
func NewObjectController(ctx context.Context, location ObjectControllerLocation) (*ObjectController, error) {
	return loadObjectController(ctx, location, openObjectControllerStore)
}

func loadObjectController(ctx context.Context, location ObjectControllerLocation, open func(context.Context, ObjectControllerLocation, bool) (*SealedStore, error)) (*ObjectController, error) {
	raw, _ := json.Marshal(location)
	_, err := ParseObjectControllerLocation(raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	store, err := open(ctx, location, false)
	if err != nil {
		return nil, err
	}
	raw, err = store.GetContext(ctx, "system", "controller", "bootstrap")
	defer clear(raw)
	store.releaseRead("system", "controller", "bootstrap")
	if err != nil || objectBootDigest(raw) != location.Digest {
		return nil, ErrDenied
	}
	c, err := ParseObjectControllerConfig(raw)
	if err != nil || validateObjectControllerBinding(location, c) != nil {
		return nil, ErrDenied
	}
	controller := &ObjectController{idle: time.Duration(c.IdleMinutes) * time.Minute, storage: location.Storage, audience: c.Audience, clock: time.Now}
	controller.renew = func(ctx context.Context, storage S3StoreConfig) error {
		return store.renewS3Credentials(ctx, "system", c.Audience, storage, nil)
	}
	var issuers []StorageLeaseIssuer
	if c.StorageIssuer != nil {
		controller.issuer, err = NewAWSStorageIssuer(*c.StorageIssuer)
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, controller.issuer)
		if err = controller.refreshControlStorage(ctx); err != nil {
			return nil, err
		}
	}
	provider := &TinfoilProvider{AdminKey: c.AdminKey, Repository: c.WorkerRepository, DomainSuffix: c.DomainSuffix}
	seed, _ := base64.StdEncoding.DecodeString(c.BootstrapPrivateKey)
	issuer := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	provisioner, err := newObjectProvisioner(provider, store, issuer, c.Owners, c.AgentRuntime, issuers...)
	clear(issuer)
	if err != nil {
		return nil, err
	}
	provider.Provisioner = provisioner
	fleet, err := NewFleet(store, provider, c.Capacity)
	if err != nil {
		return nil, err
	}
	public, _ := base64.StdEncoding.DecodeString(c.ExecutePublicKey)
	seed, _ = base64.StdEncoding.DecodeString(c.WorkerPrivateKey)
	control := &Control{Audience: c.Audience, PublicKey: public, WorkerKey: ed25519.NewKeyFromSeed(seed), Fleet: fleet, AllowedOwners: map[string]bool{}, CredentialPublicKeys: map[string]ed25519.PublicKey{}}
	clear(seed)
	for owner, policy := range c.Owners {
		control.AllowedOwners[owner] = true
		control.CredentialPublicKeys[owner], _ = base64.StdEncoding.DecodeString(policy.Browser.SecretsPublicKey)
	}
	controller.Control, controller.provisioner = control, provisioner
	if controller.issuer != nil {
		control.maintain = controller.MaintainStorage
	}
	return controller, nil
}

func (c *ObjectController) Serve(ctx context.Context) error {
	if c == nil || c.Control == nil || c.idle < time.Minute || c.idle > time.Hour {
		return ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.Control.lifetime = ctx
	done := make(chan error, 2)
	go func() { done <- Serve(ctx, ":8080", c.Control) }()
	go func() { done <- c.Control.RunIdle(ctx, c.idle) }()
	var err error
	remaining := 2
	select {
	case <-ctx.Done():
	case err = <-done:
		remaining--
	}
	cancel()
	for range remaining {
		if stopped := <-done; err == nil {
			err = stopped
		}
	}
	return err
}
