package browser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

type Instance struct {
	Owner      string `json:"owner"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
}
type Assignment struct {
	Owner    string    `json:"owner"`
	Name     string    `json:"name"`
	State    string    `json:"state"`
	Instance Instance  `json:"instance"`
	LastUsed time.Time `json:"lastUsed"`
	Users    int       `json:"-"`
}

// Provider implementations must verify immutable identity and workload policy
// before starting/stopping. A successful Stop means stopped state was observed.
type Provider interface {
	Create(context.Context, string, string) (Instance, error)
	Start(context.Context, Instance) error
	Stop(context.Context, Instance) error
	Verify(context.Context, Instance) error
}

type Fleet struct {
	mu          sync.Mutex
	store       *SealedStore
	provider    Provider
	assignments map[string]*Assignment
	limit       int
	clock       func() time.Time
}

func NewFleet(store *SealedStore, provider Provider, limit int) (*Fleet, error) {
	if store == nil || provider == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	f := &Fleet{store: store, provider: provider, assignments: map[string]*Assignment{}, limit: limit, clock: time.Now}
	raw, err := store.Get("system", "fleet", "assignments")
	if err == nil {
		if json.Unmarshal(raw, &f.assignments) != nil {
			return nil, ErrUnavailable
		}
		names := map[string]bool{}
		instances := map[string]bool{}
		for owner, a := range f.assignments {
			if a == nil || owner != a.Owner || !identifier.MatchString(owner) || !identifier.MatchString(a.Name) {
				return nil, ErrDenied
			}
			if names[a.Name] {
				return nil, ErrDenied
			}
			names[a.Name] = true
			if a.Instance.ID != "" {
				if a.Instance.Owner != owner || a.Instance.Name != a.Name || instances[a.Instance.ID] {
					return nil, ErrDenied
				}
				instances[a.Instance.ID] = true
			}
			if a.State != "stopped" && a.State != "running" && a.State != "starting" && a.State != "stopping" && a.State != "quarantined" {
				return nil, ErrDenied
			}
			a.Users = 0
			// A controller crash can interrupt a mutation. Never assume that a
			// browser is idle, stopped or safe to reassign after losing its lease.
			if a.State != "stopped" {
				a.State = "quarantined"
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	return f, nil
}

func (f *Fleet) save() error {
	raw, err := json.Marshal(f.assignments)
	if err != nil {
		return ErrUnavailable
	}
	return f.store.Put("system", "fleet", "assignments", raw)
}
func (f *Fleet) active() int {
	n := 0
	for _, a := range f.assignments {
		if a.State != "stopped" {
			n++
		}
	}
	return n
}

// Lease returns only an already-running assignment. Unlike Acquire it cannot
// create, restart, or wait for a machine after a caller authorized a mutation.
func (f *Fleet) Lease(owner string) (Instance, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.assignments[owner]
	if a == nil || a.State != "running" || a.Instance.Owner != owner {
		return Instance{}, nil, ErrUnavailable
	}
	a.Users++
	a.LastUsed = f.clock()
	return a.Instance, f.release(owner), nil
}

// Acquire reserves capacity durably before calling the cloud. Create is never
// retried after an ambiguous response. A lease covers an entire browser script.
func (f *Fleet) Acquire(ctx context.Context, owner string) (Instance, func(), error) {
	if !identifier.MatchString(owner) {
		return Instance{}, nil, ErrDenied
	}
	f.mu.Lock()
	a, exists := f.assignments[owner]
	if exists && a.State == "running" {
		a.Users++
		a.LastUsed = f.clock()
		i := a.Instance
		f.mu.Unlock()
		return i, f.release(owner), nil
	}
	if exists && a.State != "stopped" {
		f.mu.Unlock()
		return Instance{}, nil, ErrUnavailable
	}
	if f.active() >= f.limit {
		f.mu.Unlock()
		return Instance{}, nil, ErrCapacity
	}
	if !exists {
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			f.mu.Unlock()
			return Instance{}, nil, ErrUnavailable
		}
		a = &Assignment{Owner: owner, Name: "browser-" + hex.EncodeToString(nonce)}
		f.assignments[owner] = a
	}
	a.State = "starting"
	a.LastUsed = f.clock()
	if err := f.save(); err != nil {
		a.State = "quarantined"
		f.mu.Unlock()
		return Instance{}, nil, err
	}
	instance := a.Instance
	name := a.Name
	f.mu.Unlock()
	var err error
	if exists {
		err = f.provider.Start(ctx, instance)
	} else {
		instance, err = f.provider.Create(ctx, owner, name)
	}
	f.mu.Lock()
	a.Instance = instance
	if err != nil || instance.ID == "" || instance.Name != name || instance.Owner != owner {
		a.State = "quarantined"
		f.save()
		f.mu.Unlock()
		return Instance{}, nil, ErrUncertain
	}
	// Persist returned UUID before contacting its data plane or attestation.
	if err = f.save(); err != nil {
		a.State = "quarantined"
		f.mu.Unlock()
		return Instance{}, nil, ErrUncertain
	}
	f.mu.Unlock()
	if !exists {
		err = f.provider.Start(ctx, instance)
	}
	if err == nil {
		err = f.provider.Verify(ctx, instance)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		a.State = "quarantined"
		f.save()
		return Instance{}, nil, ErrDenied
	}
	a.State = "running"
	a.Users = 1
	a.LastUsed = f.clock()
	if err = f.save(); err != nil {
		a.State = "quarantined"
		return Instance{}, nil, ErrUncertain
	}
	return instance, f.release(owner), nil
}

func (f *Fleet) release(owner string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			if a := f.assignments[owner]; a != nil {
				if a.Users > 0 {
					a.Users--
				}
				a.LastUsed = f.clock()
				if f.save() != nil {
					a.State = "quarantined"
				}
			}
		})
	}
}

func (f *Fleet) StopIdle(ctx context.Context, idle time.Duration) (int, error) {
	if idle < time.Minute {
		return 0, ErrInvalid
	}
	stopped := 0
	f.mu.Lock()
	var candidates []Assignment
	for _, a := range f.assignments {
		if a.State == "running" && a.Users == 0 && f.clock().Sub(a.LastUsed) >= idle {
			a.State = "stopping"
			candidates = append(candidates, *a)
		}
	}
	if len(candidates) > 0 {
		if err := f.save(); err != nil {
			for _, a := range candidates {
				f.assignments[a.Owner].State = "quarantined"
			}
			f.mu.Unlock()
			return 0, err
		}
	}
	f.mu.Unlock()
	var failed bool
	// Slow cloud shutdown must not serialize the entire idle fleet. All
	// candidates already retain their capacity in the durable stopping state.
	jobs := make(chan Assignment)
	var workers sync.WaitGroup
	for range min(8, len(candidates)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for a := range jobs {
				err := f.provider.Stop(ctx, a.Instance)
				f.mu.Lock()
				current := f.assignments[a.Owner]
				if err != nil {
					current.State = "quarantined"
					failed = true
				} else {
					current.State = "stopped"
					stopped++
				}
				if f.save() != nil {
					current.State = "quarantined"
					failed = true
				}
				f.mu.Unlock()
			}
		}()
	}
	for _, a := range candidates {
		jobs <- a
	}
	close(jobs)
	workers.Wait()
	if failed {
		return stopped, ErrUncertain
	}
	return stopped, nil
}
