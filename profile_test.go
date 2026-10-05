package browser

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privateProfileRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
func profileFixture(t *testing.T) (*SealedStore, *testBlobBackend, []byte) {
	t.Helper()
	s, b, key := testRemoteStore(t)
	if err := ProvisionProfile(context.Background(), s, "alice"); err != nil {
		t.Fatal(err)
	}
	return s, b, key
}
func reopenProfileStore(t *testing.T, b *testBlobBackend, key []byte) *SealedStore {
	t.Helper()
	s, err := newRemoteSealedStore(context.Background(), "alice", "worker", key, b, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProfileCheckpointRecoversAcrossEmptyFilesystems(t *testing.T) {
	s, b, key := profileFixture(t)
	ctx := context.Background()
	root := privateProfileRoot(t)
	p, err := openProfile(ctx, s, "alice", root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(p.root, "Default"), 0700); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("synthetic-browser-state"), 400000) // More than one encrypted chunk.
	if err = os.WriteFile(filepath.Join(p.root, "Default", "Cookies"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.saveClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if err = p.saveClosed(ctx); err == nil {
		t.Fatal("checkpoint repeated")
	}
	for _, blob := range b.objects {
		if bytes.Contains(blob.data, []byte("synthetic-browser-state")) {
			t.Fatal("profile plaintext left trusted storage")
		}
	}
	newRoot := privateProfileRoot(t)
	fresh := reopenProfileStore(t, b, key)
	restored, err := openProfile(ctx, fresh, "alice", newRoot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restored.root, "Default", "Cookies"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("profile did not survive complete local loss", err)
	}
	meta, _ := os.Stat(filepath.Join(restored.root, "Default", "Cookies"))
	if meta.Mode().Perm() != 0600 {
		t.Fatal("restored file permissions")
	}
	if len(fresh.remote.versions) != 1 {
		t.Fatal("chunk compare tokens leaked", len(fresh.remote.versions))
	}
	if _, err = openProfile(ctx, reopenProfileStore(t, b, key), "alice", privateProfileRoot(t)); !errors.Is(err, ErrUncertain) {
		t.Fatal("another process reopened active profile", err)
	}
	if err = ProvisionProfile(ctx, reopenProfileStore(t, b, key), "alice"); err == nil {
		t.Fatal("provisioning cleared active state")
	}
}

func TestProfileCrashAndInterruptedCheckpointsStayQuarantined(t *testing.T) {
	for _, stage := range []string{"crash", "chunk-not-saved", "chunk-ack-lost", "head-not-saved", "head-ack-lost"} {
		t.Run(stage, func(t *testing.T) {
			s, b, key := profileFixture(t)
			ctx := context.Background()
			p, err := openProfile(ctx, s, "alice", privateProfileRoot(t))
			if err != nil {
				t.Fatal(err)
			}
			if stage != "crash" {
				b.failAt = b.writes + 1
				if strings.HasPrefix(stage, "head-") {
					b.failAt++
				}
				b.commitFailed = strings.HasSuffix(stage, "ack-lost")
				if err = p.saveClosed(ctx); err == nil {
					t.Fatal("interrupted save succeeded")
				}
				if err = p.saveClosed(ctx); err == nil {
					t.Fatal("save automatically retried")
				}
			}
			b.failAt = 0
			_, err = openProfile(ctx, reopenProfileStore(t, b, key), "alice", privateProfileRoot(t))
			if stage == "head-ack-lost" {
				if err != nil {
					t.Fatal("fully committed clean checkpoint could not reconcile", err)
				}
			} else if !errors.Is(err, ErrUncertain) {
				t.Fatal("unclean profile silently restored", err)
			}
		})
	}
}

func TestProfileCheckpointRejectsFilesystemLinks(t *testing.T) {
	for _, hard := range []bool{false, true} {
		root := privateProfileRoot(t)
		outside := filepath.Join(privateProfileRoot(t), "secret")
		if err := os.WriteFile(outside, []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
		var err error
		if hard {
			err = os.Link(outside, filepath.Join(root, "link"))
		} else {
			err = os.Symlink(outside, filepath.Join(root, "link"))
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = packProfile(context.Background(), root); err == nil {
			t.Fatal("linked file archived")
		}
	}
}

func TestProfileSkipsOnlyRebuildableFontCache(t *testing.T) {
	root := privateProfileRoot(t)
	cache := filepath.Join(root, ".cache", "fontconfig")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(privateProfileRoot(t), "system-font-cache")
	if err := os.WriteFile(outside, []byte("must-not-be-archived"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cache, "cache-v1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "browser-state"), []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := packProfile(context.Background(), root)
	if err != nil || bytes.Contains(data, []byte("must-not-be-archived")) {
		t.Fatal("font cache was followed", err)
	}
	restored := privateProfileRoot(t)
	if err = unpackProfile(context.Background(), restored, data); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(filepath.Join(restored, ".cache", "fontconfig")); !os.IsNotExist(err) {
		t.Fatal("font cache was restored")
	}
	if saved, err := os.ReadFile(filepath.Join(restored, "browser-state")); err != nil || string(saved) != "preserved" {
		t.Fatal("browser state was dropped")
	}
	if err = os.Symlink(outside, filepath.Join(root, ".cache", "other")); err != nil {
		t.Fatal(err)
	}
	if _, err = packProfile(context.Background(), root); err == nil {
		t.Fatal("non-font-cache link was allowed")
	}
}

func TestProfileRestoreRejectsEscapesSpecialFilesAndConflicts(t *testing.T) {
	for _, headers := range [][]*tar.Header{
		{{Name: "../escape", Typeflag: tar.TypeReg}}, {{Name: "/escape", Typeflag: tar.TypeReg}},
		{{Name: "a/../escape", Typeflag: tar.TypeReg}}, {{Name: `a\escape`, Typeflag: tar.TypeReg}},
		{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}}, {{Name: "link", Typeflag: tar.TypeLink, Linkname: "../outside"}},
		{{Name: "pipe", Typeflag: tar.TypeFifo}}, {{Name: "device", Typeflag: tar.TypeChar}},
		{{Name: "parent/file", Typeflag: tar.TypeReg}},
		{{Name: "same", Typeflag: tar.TypeReg}, {Name: "same", Typeflag: tar.TypeReg}},
		{{Name: "same", Typeflag: tar.TypeReg}, {Name: "same/child", Typeflag: tar.TypeReg}},
		{{Name: "huge", Typeflag: tar.TypeReg, Size: maxProfileBytes + 1}},
	} {
		var data bytes.Buffer
		w := tar.NewWriter(&data)
		for _, h := range headers {
			if err := w.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
		}
		w.Close()
		if err := unpackProfile(context.Background(), privateProfileRoot(t), data.Bytes()); err == nil {
			t.Fatal("unsafe archive accepted", headers[0].Name, headers[0].Typeflag)
		}
	}
}

func TestProfileCorruptManifestOrChunkNeverStarts(t *testing.T) {
	for _, damage := range []string{"digest", "chunks", "extra-field", "missing-head", "corrupt-chunk"} {
		t.Run(damage, func(t *testing.T) {
			s, b, key := profileFixture(t)
			ctx := context.Background()
			p, err := openProfile(ctx, s, "alice", privateProfileRoot(t))
			if err != nil {
				t.Fatal(err)
			}
			if err = p.saveClosed(ctx); err != nil {
				t.Fatal(err)
			}
			data, err := s.GetContext(ctx, "alice", "profile", "head")
			if err != nil {
				t.Fatal(err)
			}
			h, _ := decodeProfileState(data)
			switch damage {
			case "digest":
				h.Archive.Digest = strings.Repeat("0", 64)
			case "chunks":
				h.Archive.Chunks++
			case "extra-field":
				data = append(data[:len(data)-1], []byte(`,"unsafe":true}`)...)
			case "missing-head":
				_, path, _, _ := s.binding("alice", "profile", "head")
				delete(b.objects, filepath.Base(path))
			case "corrupt-chunk":
				_, path, _, _ := s.binding("alice", "profile-chunk", profileChunkName(h.Archive.ID, 0))
				v := b.objects[filepath.Base(path)]
				v.data[len(v.data)-1] ^= 1
				b.objects[filepath.Base(path)] = v
			}
			if damage == "digest" || damage == "chunks" {
				data, _ = json.Marshal(h)
			}
			if damage == "digest" || damage == "chunks" || damage == "extra-field" {
				if err = s.PutContext(ctx, "alice", "profile", "head", data); err != nil {
					t.Fatal(err)
				}
			}
			root := privateProfileRoot(t)
			if _, err = openProfile(ctx, reopenProfileStore(t, b, key), "alice", root); err == nil {
				t.Fatal("damaged checkpoint opened")
			}
			if _, err = os.Stat(filepath.Join(root, "profile")); !os.IsNotExist(err) {
				t.Fatal("partial profile published")
			}
		})
	}
}

func TestProfileManifestBounds(t *testing.T) {
	zero := sha256.Sum256(nil)
	for _, a := range []profileArchive{
		{ID: strings.Repeat("a", 32), Bytes: maxProfileBytes + 1, Digest: hex.EncodeToString(zero[:]), Chunks: 33},
		{ID: "../escape", Bytes: 1024, Digest: hex.EncodeToString(zero[:]), Chunks: 1},
	} {
		data, _ := json.Marshal(profileState{Version: 1, State: "closed", Archive: &a})
		if _, err := decodeProfileState(data); err == nil {
			t.Fatal("unbounded manifest accepted")
		}
	}
}

func TestProfileCompetingStartsHaveOneExclusiveOwner(t *testing.T) {
	s, b, key := profileFixture(t)
	other := reopenProfileStore(t, b, key)
	_, head, _, _ := s.binding("alice", "profile", "head")
	b.barrierKey, b.barrier, b.barrierExisting = filepath.Base(head), make(chan struct{}), true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		profile *profileCheckpoint
		err     error
	}
	results := make(chan result, 2)
	for _, store := range []*SealedStore{s, other} {
		root := privateProfileRoot(t)
		go func() { p, err := openProfile(ctx, store, "alice", root); results <- result{p, err} }()
	}
	a, z := <-results, <-results
	if (a.err == nil) == (z.err == nil) {
		t.Fatal("profile acquired twice or neither won", a.err, z.err)
	}
	if a.err != nil {
		a = z
	}
	if err := a.profile.saveClosed(ctx); err != nil {
		t.Fatal("winning writer lost authority", err)
	}
}

func TestProfileSessionCiphertextIsBoundAndRequired(t *testing.T) {
	s, b, key := profileFixture(t)
	ctx := context.Background()
	p, err := openProfile(ctx, s, "alice", privateProfileRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"version":1,"cookies":[],"synthetic":"private-cookie-fixture"}`)
	if err = p.saveClosedSession(ctx, secret); err != nil {
		t.Fatal(err)
	}
	for _, blob := range b.objects {
		if bytes.Contains(blob.data, secret) {
			t.Fatal("session plaintext uploaded")
		}
	}
	head, err := s.GetContext(ctx, "alice", "profile", "head")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := decodeProfileState(head)
	_, name, _, _ := s.binding("alice", "profile-session", h.Archive.ID)
	blob := b.objects[filepath.Base(name)]
	blob.data[len(blob.data)-1] ^= 1
	b.objects[filepath.Base(name)] = blob
	root := privateProfileRoot(t)
	if _, err = openProfile(ctx, reopenProfileStore(t, b, key), "alice", root); err == nil {
		t.Fatal("missing authentic session silently ignored")
	}
	if _, err = os.Stat(filepath.Join(root, "profile")); !os.IsNotExist(err) {
		t.Fatal("partial profile published")
	}
}
