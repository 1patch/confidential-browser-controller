package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
)

type ObjectBootstrap struct {
	Browser Bootstrap     `json:"browser"`
	Storage S3StoreConfig `json:"storage"`
}

func ParseObjectBootstrap(raw []byte) (ObjectBootstrap, error) {
	var c ObjectBootstrap
	if len(raw) > 64<<10 {
		return c, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Browser.InferenceKey != "" {
		return ObjectBootstrap{}, ErrInvalid
	}
	encoded, _ := json.Marshal(c.Browser)
	defer clear(encoded)
	if _, err := ParseBootstrap(encoded); err != nil {
		return ObjectBootstrap{}, ErrInvalid
	}
	if _, err := newS3BlobBackend(c.Storage, c.Browser.Owner, c.Browser.Audience, nil); err != nil {
		return ObjectBootstrap{}, ErrInvalid
	}
	return c, nil
}

// NewObjectWorker never provisions or replaces missing storage. The trusted
// provisioner must first create the encrypted identity and closed profile head.
// Its executable requires a private RAM filesystem and fresh attested bootstrap.
func NewObjectWorker(ctx context.Context, c ObjectBootstrap, root, executable string) (*Worker, error) {
	encoded, _ := json.Marshal(c)
	_, err := ParseObjectBootstrap(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	key, _ := base64.StdEncoding.DecodeString(c.Browser.StorageKey)
	defer clear(key)
	store, err := NewS3SealedStore(ctx, c.Storage, c.Browser.Owner, c.Browser.Audience, key, false)
	if err != nil {
		return nil, startupFailure("storage-identity", err)
	}
	return newObjectWorker(ctx, c.Browser, root, executable, store)
}

func newObjectWorker(ctx context.Context, c Bootstrap, root, executable string, store *SealedStore) (*Worker, error) {
	if c.InferenceKey != "" || store == nil {
		return nil, ErrDenied
	}
	if err := bindDirectory(root, c.Owner, c.Audience, c.StorageKey); err != nil {
		return nil, startupFailure("profile-binding", err)
	}
	checkpoint, err := openProfile(ctx, store, c.Owner, root)
	if err != nil {
		return nil, startupFailure("profile-open", err)
	}
	w := boundBrowserWorker(c, root, executable, store)
	w.checkpoint = checkpoint.saveClosedSession
	w.restoreSession = checkpoint.restoreSession
	w.shutdownTimeout = 90 * time.Second
	return w, nil
}
