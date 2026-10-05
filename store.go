package browser

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// SealedStore contains only ciphertext on disk. The key must be delivered to an
// attested trusted service; it must never be mounted in an agent Bash workspace.
type SealedStore struct {
	root   string
	key    [32]byte
	mu     sync.Mutex
	remote *remoteSealedState
}

func NewSealedStore(root string, key []byte) (*SealedStore, error) {
	if len(key) != 32 || !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	s := &SealedStore{root: root}
	copy(s.key[:], key)
	return s, nil
}

func (s *SealedStore) binding(owner, purpose, name string) ([]byte, string, cipher.AEAD, error) {
	if !identifier.MatchString(owner) || !identifier.MatchString(purpose) || !identifier.MatchString(name) {
		return nil, "", nil, ErrInvalid
	}
	if s.remote != nil && owner != s.remote.owner {
		return nil, "", nil, ErrDenied
	}
	associated := []byte("sure-browser/v1\x00" + owner + "\x00" + purpose + "\x00" + name)
	derive := hmac.New(sha256.New, s.key[:])
	derive.Write([]byte("owner-key/v1\x00" + owner))
	block, err := aes.NewCipher(derive.Sum(nil))
	if err != nil {
		return nil, "", nil, ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", nil, ErrUnavailable
	}
	index := hmac.New(sha256.New, s.key[:])
	index.Write(associated)
	return associated, filepath.Join(s.root, hex.EncodeToString(index.Sum(nil))+".sealed"), aead, nil
}

func (s *SealedStore) Put(owner, purpose, name string, plain []byte) error {
	return s.PutContext(context.Background(), owner, purpose, name, plain)
}

func (s *SealedStore) PutContext(ctx context.Context, owner, purpose, name string, plain []byte) error {
	return s.putContext(ctx, owner, purpose, name, plain, false)
}

// CreateContext reserves a new record atomically, including when two processes
// share remote storage. A prior read alone cannot establish exclusive execution.
func (s *SealedStore) CreateContext(ctx context.Context, owner, purpose, name string, plain []byte) error {
	return s.putContext(ctx, owner, purpose, name, plain, true)
}

func (s *SealedStore) putContext(ctx context.Context, owner, purpose, name string, plain []byte, create bool) error {
	if len(plain) > 32<<20 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	ad, path, aead, err := s.binding(owner, purpose, name)
	if err != nil {
		return err
	}
	if s.remote != nil {
		return s.putRemoteLocked(ctx, owner, purpose, name, plain, create)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrUnavailable
	}
	sealed := aead.Seal(nonce, nonce, plain, ad)
	f, err := os.CreateTemp(s.root, ".write-*")
	if err != nil {
		return ErrUnavailable
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(sealed)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	if create {
		err = os.Link(f.Name(), path)
	} else {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return ErrUnavailable
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *SealedStore) Get(owner, purpose, name string) ([]byte, error) {
	return s.GetContext(context.Background(), owner, purpose, name)
}

func (s *SealedStore) GetContext(ctx context.Context, owner, purpose, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	ad, path, aead, err := s.binding(owner, purpose, name)
	if err != nil {
		return nil, err
	}
	if s.remote != nil {
		return s.getRemoteLocked(ctx, owner, purpose, name)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 33<<20 {
		return nil, ErrDenied
	}
	sealed, err := os.ReadFile(path)
	if err != nil || len(sealed) < aead.NonceSize() {
		return nil, ErrDenied
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	if err != nil {
		return nil, ErrDenied
	}
	return plain, nil
}
