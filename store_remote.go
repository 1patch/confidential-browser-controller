package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// sealedBlobBackend handles ciphertext only. Empty version means create only;
// every update must compare the version actually read. No mutation retries.
type sealedBlobBackend interface {
	Get(context.Context, string) ([]byte, string, error)
	Put(context.Context, string, []byte, string) (string, error)
}

type remoteSealedState struct {
	owner    string
	backend  sealedBlobBackend
	versions map[string]string
	blocked  bool
}

// Release a completed operation's compare token. The worker holds its operation
// mutex until this returns, so another call cannot lose a token it just read.
func (s *SealedStore) releaseRead(owner, purpose, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remote == nil {
		return
	}
	_, path, _, err := s.binding(owner, purpose, name)
	if err == nil {
		delete(s.remote.versions, filepath.Base(path))
	}
}

// initialize belongs to the trusted provisioning path. Workers reopen with it
// false: a missing identity must not silently become a new browser or new key.
func newRemoteSealedStore(ctx context.Context, owner, audience string, key []byte, backend sealedBlobBackend, initialize bool) (*SealedStore, error) {
	if !identifier.MatchString(owner) || !identifier.MatchString(audience) || len(key) != 32 || backend == nil {
		return nil, ErrInvalid
	}
	s := &SealedStore{remote: &remoteSealedState{owner: owner, backend: backend, versions: map[string]string{}}}
	copy(s.key[:], key)
	identity, _ := json.Marshal(struct{ Owner, Audience string }{owner, audience})
	ad, _, aead, err := s.binding(owner, "identity", "binding")
	if err != nil {
		return nil, err
	}
	// The fixed slot is deliberate: a wrong key must fail decryption, rather than
	// produce a different keyed filename that looks like uninitialized storage.
	const slot = "identity.sealed"
	sealed, _, err := backend.Get(ctx, slot)
	if errors.Is(err, os.ErrNotExist) && initialize {
		nonce := make([]byte, aead.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, ErrUnavailable
		}
		sealed = aead.Seal(nonce, nonce, identity, ad)
		if _, err = backend.Put(ctx, slot, sealed, ""); err != nil {
			return nil, ErrUncertain
		}
		return s, nil
	}
	if err != nil || len(sealed) < aead.NonceSize() {
		return nil, ErrDenied
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	if err != nil || !bytes.Equal(plain, identity) {
		return nil, ErrDenied
	}
	return s, nil
}

func (s *SealedStore) getRemoteLocked(ctx context.Context, owner, purpose, name string) ([]byte, error) {
	r := s.remote
	if r.blocked {
		return nil, ErrUncertain
	}
	ad, path, aead, err := s.binding(owner, purpose, name)
	if err != nil {
		return nil, err
	}
	object := filepath.Base(path)
	sealed, version, err := r.backend.Get(ctx, object)
	if errors.Is(err, os.ErrNotExist) {
		r.versions[object] = ""
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(sealed) < aead.NonceSize() || len(sealed) > 33<<20 || version == "" {
		r.blocked = true
		return nil, ErrDenied
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	if err != nil {
		r.blocked = true
		return nil, ErrDenied
	}
	r.versions[object] = version
	return plain, nil
}

func (s *SealedStore) putRemoteLocked(ctx context.Context, owner, purpose, name string, plain []byte, create bool) error {
	r := s.remote
	if r.blocked {
		return ErrUncertain
	}
	ad, path, aead, err := s.binding(owner, purpose, name)
	if err != nil {
		return err
	}
	object := filepath.Base(path)
	if _, read := r.versions[object]; !read && !create {
		if _, err = s.getRemoteLocked(ctx, owner, purpose, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrUnavailable
	}
	sealed := aead.Seal(nonce, nonce, plain, ad)
	previous := r.versions[object]
	if create {
		previous = ""
	}
	version, err := r.backend.Put(ctx, object, sealed, previous)
	if err != nil || version == "" {
		// Neither an ambiguous response nor a competing writer may be hidden by
		// a fresh read/retry. Stop this store until explicit recovery reopens it.
		r.blocked = true
		return ErrUncertain
	}
	r.versions[object] = version
	return nil
}
