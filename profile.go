package browser

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	maxProfileBytes   = 256 << 20
	profileChunkBytes = 8 << 20
	maxProfileEntries = 8192
)

type profileArchive struct {
	ID            string `json:"id"`
	Bytes         int    `json:"bytes"`
	Digest        string `json:"digest"`
	Chunks        int    `json:"chunks"`
	SessionBytes  int    `json:"sessionBytes,omitempty"`
	SessionDigest string `json:"sessionDigest,omitempty"`
}
type profileState struct {
	Version int             `json:"version"`
	State   string          `json:"state"`
	Session string          `json:"session,omitempty"`
	Archive *profileArchive `json:"archive,omitempty"`
}

// ProvisionProfile belongs to trusted, one-time provisioning. Worker startup
// never treats missing state as an empty profile or creates a replacement key.
func ProvisionProfile(ctx context.Context, store *SealedStore, owner string) error {
	if store == nil || !identifier.MatchString(owner) {
		return ErrInvalid
	}
	defer store.releaseRead(owner, "profile", "head")
	data, err := store.GetContext(ctx, owner, "profile", "head")
	if err == nil {
		h, err := decodeProfileState(data)
		if err != nil || h.State != "closed" {
			return ErrUncertain
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrDenied
	}
	data, _ = json.Marshal(profileState{Version: 1, State: "closed"})
	return store.CreateContext(ctx, owner, "profile", "head", data)
}

type profileCheckpoint struct {
	mu                sync.Mutex
	store             *SealedStore
	owner, root       string
	active, attempted bool
	session           string
	restoreSession    []byte
}

func decodeProfileState(data []byte) (profileState, error) {
	var h profileState
	if len(data) > 4096 {
		return h, ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil || d.Decode(new(any)) != io.EOF || h.Version != 1 || (h.State != "active" && h.State != "closed") {
		return h, ErrDenied
	}
	if h.State == "closed" && h.Session != "" || h.State == "active" && !hexIdentifier(h.Session, 16) {
		return h, ErrDenied
	}
	if a := h.Archive; a != nil && (!hexIdentifier(a.ID, 16) || !hexIdentifier(a.Digest, 32) || a.Bytes < 1024 || a.Bytes > maxProfileBytes || a.Chunks != (a.Bytes+profileChunkBytes-1)/profileChunkBytes) {
		return h, ErrDenied
	}
	if a := h.Archive; a != nil && (a.SessionBytes < 0 || a.SessionBytes > maxSessionBytes || a.SessionBytes == 0 && a.SessionDigest != "" || a.SessionBytes > 0 && !hexIdentifier(a.SessionDigest, 32)) {
		return h, ErrDenied
	}
	return h, nil
}

func hexIdentifier(value string, size int) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == size && hex.EncodeToString(data) == value
}

// openProfile restores only a closed checkpoint into a fresh local directory,
// then exclusively marks it active before Chromium can start. A crash leaves
// active state; a later worker cannot silently resurrect an older checkpoint.
func openProfile(ctx context.Context, store *SealedStore, owner, root string) (*profileCheckpoint, error) {
	if store == nil || !identifier.MatchString(owner) || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrInvalid
	}
	meta, err := os.Lstat(root)
	if err != nil || !meta.IsDir() || meta.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("profile root: %w", ErrDenied)
	}
	profile := filepath.Join(root, "profile")
	if _, err = os.Lstat(profile); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrDenied
	}
	data, err := store.GetContext(ctx, owner, "profile", "head")
	if err != nil {
		return nil, ErrDenied
	}
	h, err := decodeProfileState(data)
	if err != nil {
		return nil, err
	}
	if h.State != "closed" {
		return nil, ErrUncertain
	}
	staging, err := os.MkdirTemp(root, ".restore-")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer os.RemoveAll(staging)
	var restoredSession []byte
	if h.Archive != nil {
		archive, err := readProfileArchive(ctx, store, owner, *h.Archive)
		if err != nil {
			return nil, err
		}
		if err = unpackProfile(ctx, staging, archive); err != nil {
			return nil, err
		}
		if h.Archive.SessionBytes > 0 {
			restoredSession, err = store.GetContext(ctx, owner, "profile-session", h.Archive.ID)
			store.releaseRead(owner, "profile-session", h.Archive.ID)
			digest := sha256.Sum256(restoredSession)
			if err != nil || len(restoredSession) != h.Archive.SessionBytes || hex.EncodeToString(digest[:]) != h.Archive.SessionDigest {
				return nil, ErrDenied
			}
		}
	}
	session := make([]byte, 16)
	if _, err = rand.Read(session); err != nil {
		return nil, ErrUnavailable
	}
	h.State, h.Session = "active", hex.EncodeToString(session)
	data, _ = json.Marshal(h)
	if err = store.PutContext(ctx, owner, "profile", "head", data); err != nil {
		return nil, ErrUncertain
	}
	if ctx.Err() != nil || os.Rename(staging, profile) != nil {
		return nil, ErrUncertain
	}
	return &profileCheckpoint{store: store, owner: owner, root: profile, session: h.Session, active: true, restoreSession: restoredSession}, nil
}

// saveClosed is called only by the worker after Chromium confirms clean shutdown.
// Chunks are immutable; only the final conditional head update publishes a usable
// checkpoint. Failed saves leave active state and cannot be retried automatically.
func (p *profileCheckpoint) saveClosed(ctx context.Context) error {
	return p.saveClosedSession(ctx, nil)
}

func (p *profileCheckpoint) saveClosedSession(ctx context.Context, session []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.attempted {
		return ErrUncertain
	}
	p.attempted = true
	defer p.store.releaseRead(p.owner, "profile", "head")
	if len(session) > maxSessionBytes {
		return ErrCapacity
	}
	data, err := packProfile(ctx, p.root)
	if err != nil {
		return err
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return ErrUnavailable
	}
	digest := sha256.Sum256(data)
	a := profileArchive{ID: hex.EncodeToString(id), Bytes: len(data), Digest: hex.EncodeToString(digest[:]), Chunks: (len(data) + profileChunkBytes - 1) / profileChunkBytes}
	for i := 0; i < a.Chunks; i++ {
		end := min((i+1)*profileChunkBytes, len(data))
		name := profileChunkName(a.ID, i)
		err = p.store.CreateContext(ctx, p.owner, "profile-chunk", name, data[i*profileChunkBytes:end])
		p.store.releaseRead(p.owner, "profile-chunk", name)
		if err != nil {
			return ErrUncertain
		}
	}
	if len(session) > 0 {
		digest := sha256.Sum256(session)
		a.SessionBytes, a.SessionDigest = len(session), hex.EncodeToString(digest[:])
		err = p.store.CreateContext(ctx, p.owner, "profile-session", a.ID, session)
		p.store.releaseRead(p.owner, "profile-session", a.ID)
		if err != nil {
			return ErrUncertain
		}
	}
	head, _ := json.Marshal(profileState{Version: 1, State: "closed", Archive: &a})
	if err = p.store.PutContext(ctx, p.owner, "profile", "head", head); err != nil {
		return ErrUncertain
	}
	p.active = false
	return nil
}

func profileChunkName(id string, i int) string { return fmt.Sprintf("%s-%04d", id, i) }

func readProfileArchive(ctx context.Context, store *SealedStore, owner string, a profileArchive) ([]byte, error) {
	data := make([]byte, 0, a.Bytes)
	for i := 0; i < a.Chunks; i++ {
		name := profileChunkName(a.ID, i)
		chunk, err := store.GetContext(ctx, owner, "profile-chunk", name)
		store.releaseRead(owner, "profile-chunk", name)
		if err != nil || len(chunk) != min(profileChunkBytes, a.Bytes-len(data)) {
			return nil, ErrDenied
		}
		data = append(data, chunk...)
	}
	digest := sha256.Sum256(data)
	if len(data) != a.Bytes || hex.EncodeToString(digest[:]) != a.Digest {
		return nil, ErrDenied
	}
	return data, nil
}

type profileBuffer struct{ bytes.Buffer }

func (b *profileBuffer) Write(data []byte) (int, error) {
	if len(data) > maxProfileBytes-b.Len() {
		return 0, ErrCapacity
	}
	return b.Buffer.Write(data)
}

func profilePath(name string) bool {
	return name != "." && len(name) <= 1024 && filepath.IsLocal(name) && path.Clean(name) == name && !strings.ContainsAny(name, "\\\x00") && len(strings.Split(name, "/")) <= 32
}

func packProfile(ctx context.Context, root string) ([]byte, error) {
	meta, err := os.Lstat(root)
	if err != nil || !meta.IsDir() || meta.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	var buffer profileBuffer
	w := tar.NewWriter(&buffer)
	entries := 0
	err = filepath.WalkDir(root, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return ErrUnavailable
		}
		if file == root {
			return nil
		}
		entries++
		if entries > maxProfileEntries {
			return ErrCapacity
		}
		rel, err := filepath.Rel(root, file)
		name := filepath.ToSlash(rel)
		if err != nil || !profilePath(name) {
			return fmt.Errorf("profile path: %w", ErrDenied)
		}
		// HOME is this private profile directory. Linux Chrome's launcher may
		// populate a fontconfig cache here with links to system font caches.
		// It is rebuildable OS data, not browser state; never follow or restore
		// it. Every link outside this exact subtree is still rejected.
		if name == ".cache/fontconfig" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil || !(info.IsDir() || info.Mode().IsRegular()) || info.Size() > maxProfileBytes {
			return fmt.Errorf("profile entry metadata: %w", ErrDenied)
		}
		if info.Mode().IsRegular() {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Nlink != 1 {
				return fmt.Errorf("profile file alias: %w", ErrDenied)
			}
		}
		header := &tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: info.Size()}
		if info.IsDir() {
			header.Typeflag, header.Mode, header.Size = tar.TypeDir, 0700, 0
		}
		if err = w.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		fd, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("profile file open: %w", ErrDenied)
		}
		f := os.NewFile(uintptr(fd), file)
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
			return fmt.Errorf("profile file changed: %w", ErrDenied)
		}
		if _, err = io.CopyN(w, f, info.Size()); err != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func unpackProfile(ctx context.Context, root string, data []byte) error {
	if len(data) > maxProfileBytes {
		return ErrCapacity
	}
	r := tar.NewReader(bytes.NewReader(data))
	directories := map[string]bool{".": true}
	seen := map[string]bool{}
	for entries := 0; ; entries++ {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		h, err := r.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil || entries >= maxProfileEntries || !profilePath(h.Name) || seen[h.Name] || !directories[path.Dir(h.Name)] || h.Size < 0 || h.Size > maxProfileBytes {
			return ErrDenied
		}
		seen[h.Name] = true
		target := filepath.Join(root, filepath.FromSlash(h.Name))
		switch h.Typeflag {
		case tar.TypeDir:
			if h.Size != 0 || os.Mkdir(target, 0700) != nil {
				return ErrDenied
			}
			directories[h.Name] = true
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return ErrDenied
			}
			_, writeErr := io.CopyN(f, r, h.Size)
			if writeErr == nil {
				writeErr = f.Sync()
			}
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil {
				return ErrDenied
			}
		default:
			return ErrDenied
		}
	}
}
