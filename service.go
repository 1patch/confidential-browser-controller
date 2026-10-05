package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Bootstrap is delivered by the private, attestation-verifying keyserver. It is
// never assembled from model arguments, ordinary cloud variables or URL params.
type Bootstrap struct {
	Version           int      `json:"version"`
	Owner             string   `json:"owner"`
	Audience          string   `json:"audience"`
	ExecutePublicKey  string   `json:"executePublicKey"`
	SecretsPublicKey  string   `json:"secretsPublicKey"`
	StorageKey        string   `json:"storageKey"`
	Origins           []string `json:"origins"`
	CredentialOrigins []string `json:"credentialOrigins"`
	AllowWrites       bool     `json:"allowWrites"`
	InferenceKey      string   `json:"inferenceKey,omitempty"`
}

func ParseBootstrap(raw []byte) (Bootstrap, error) {
	var c Bootstrap
	if len(raw) > 32<<10 {
		return c, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(new(any)) != io.EOF || c.Version != 1 || !identifier.MatchString(c.Owner) || !identifier.MatchString(c.Audience) {
		return Bootstrap{}, ErrInvalid
	}
	for _, key := range []string{c.ExecutePublicKey, c.SecretsPublicKey, c.StorageKey} {
		b, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != key {
			return Bootstrap{}, ErrInvalid
		}
	}
	if c.ExecutePublicKey == c.SecretsPublicKey || len(c.Origins) < 1 || len(c.Origins) > 128 || len(c.CredentialOrigins) > 32 {
		return Bootstrap{}, ErrInvalid
	}
	if len(c.InferenceKey) > 4096 || strings.ContainsAny(c.InferenceKey, " \t\r\n") {
		return Bootstrap{}, ErrInvalid
	}
	for _, origin := range append(append([]string{}, c.Origins...), c.CredentialOrigins...) {
		// Origins are canonical, exact HTTPS hostnames. IP literals are forbidden.
		host := strings.TrimPrefix(origin, "https://")
		if host == origin || strings.ContainsAny(host, "/:@?#%\\") || host != strings.ToLower(host) || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || (NetworkPolicy{Origins: c.Origins}).CheckURL(origin) != nil {
			return Bootstrap{}, ErrInvalid
		}
	}
	return c, nil
}

// LockDirectory prevents two worker/controller processes from using one journal
// or profile. A process crash releases the kernel lock without deleting state.
func LockDirectory(root string) (func(), error) {
	if !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, ErrUnavailable
	}
	meta, err := os.Lstat(root)
	if err != nil || !meta.IsDir() || meta.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	fd, err := syscall.Open(filepath.Join(root, "service.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		return nil, ErrUnavailable
	}
	return func() { syscall.Flock(fd, syscall.LOCK_UN); syscall.Close(fd) }, nil
}

// NewBrowserWorker constructs the generic browser service without application
// code. Reject accidentally supplied inference credentials before touching disk.
func NewBrowserWorker(c Bootstrap, root, executable string) (*Worker, error) {
	if c.InferenceKey != "" {
		return nil, ErrDenied
	}
	encoded, _ := json.Marshal(c)
	if _, err := ParseBootstrap(encoded); err != nil {
		return nil, err
	}
	key, _ := base64.StdEncoding.DecodeString(c.StorageKey)
	store, err := NewSealedStore(filepath.Join(root, "sealed"), key)
	if err != nil {
		return nil, err
	}
	if err = bindDirectory(root, c.Owner, c.Audience, c.StorageKey); err != nil {
		return nil, err
	}
	return boundBrowserWorker(c, root, executable, store), nil
}

func boundBrowserWorker(c Bootstrap, root, executable string, store *SealedStore) *Worker {
	pub, _ := base64.StdEncoding.DecodeString(c.ExecutePublicKey)
	secretsPub, _ := base64.StdEncoding.DecodeString(c.SecretsPublicKey)
	policy := NetworkPolicy{Origins: c.Origins}
	w := &Worker{Owner: c.Owner, Audience: c.Audience, PublicKey: ed25519.PublicKey(pub), SecretsPublicKey: ed25519.PublicKey(secretsPub), Store: store,
		CredentialPolicy: NetworkPolicy{Origins: c.CredentialOrigins}, Sandbox: Sandbox{Safety: StubSafety{Policy: policy, AllowWrites: c.AllowWrites}}}
	w.CreateDriver = func(ctx context.Context) (Driver, error) {
		return NewChrome(ctx, ChromeConfig{Executable: executable, ProfileDirectory: filepath.Join(root, "profile"), Policy: policy})
	}
	return w
}

func bindDirectory(root, owner, audience, key string) error {
	// The fixed filename detects a wrong storage key as well as a wrong owner;
	// a keyed filename would incorrectly look absent after a key change.
	marker := sha256.Sum256([]byte("sure-browser/volume/v1\x00" + owner + "\x00" + audience + "\x00" + key))
	markerPath := filepath.Join(root, "identity")
	fd, err := syscall.Open(markerPath, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		file := os.NewFile(uintptr(fd), markerPath)
		_, err = file.Write(marker[:])
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err == nil {
			dir, e := os.Open(root)
			if e != nil {
				err = e
			} else {
				err = dir.Sync()
				dir.Close()
			}
		}
	} else if os.IsExist(err) {
		meta, e := os.Lstat(markerPath)
		if e != nil || !meta.Mode().IsRegular() || meta.Mode().Perm()&0077 != 0 || meta.Size() != 32 {
			return ErrDenied
		}
		saved, e := os.ReadFile(markerPath)
		err = e
		if err == nil && !bytes.Equal(saved, marker[:]) {
			err = ErrDenied
		}
	}
	if err != nil {
		return ErrDenied
	}
	return nil
}

// ServeWorker drains requests and closes Chromium before cancelling its lifetime.
// Binding Chrome directly to the signal context would kill it before its graceful
// close, losing profile flushes and reporting every ordinary stop as a failure.
func ServeWorker(ctx context.Context, address string, worker *Worker) error {
	return serveWorker(ctx, address, worker, Serve)
}

func serveWorker(ctx context.Context, address string, worker *Worker, serve func(context.Context, string, http.Handler) error) error {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A stop during startup still interrupts initialization. Once ready, shutdown
	// owns the ordering: drain HTTP, stop Pi, flush Chromium, cancel its lifetime.
	stopInitialization := context.AfterFunc(ctx, cancel)
	err := worker.Initialize(lifetime)
	stopInitialization()
	if err != nil {
		return err
	}
	err = serve(ctx, address, worker)
	grace := worker.shutdownTimeout
	if grace <= 0 || grace > 90*time.Second {
		grace = 10 * time.Second
	}
	closing, stop := context.WithTimeout(context.Background(), grace)
	defer stop()
	closeErr := worker.Close(closing)
	if err == nil {
		err = closeErr
	}
	return err
}

// Serve terminates TLS at the measured enclave shim. The worker has no public
// listener outside that enclave network, and every effectful route is signed.
func Serve(ctx context.Context, address string, handler http.Handler) error {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return ErrUnavailable
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if server.Shutdown(stop) != nil {
			server.Close()
		}
		return nil
	}
}
