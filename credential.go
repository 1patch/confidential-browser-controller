package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

type CookieCredential struct {
	Name       string `json:"name"`
	Origin     string `json:"origin"`
	CookieName string `json:"cookieName"`
	Value      string `json:"value"`
}

var cookieName = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,100}$`)

func (c CookieCredential) Validate(policy NetworkPolicy) error {
	if !identifier.MatchString(c.Name) || !cookieName.MatchString(c.CookieName) || len(c.Value) < 1 || len(c.Value) > 8192 || strings.ContainsAny(c.Value, "\r\n\x00;") || policy.CheckURL(c.Origin) != nil {
		return ErrInvalid
	}
	for _, ch := range []byte(c.Value) {
		if ch < 0x21 || ch > 0x7e || ch == '"' || ch == ',' || ch == '\\' {
			return ErrInvalid
		}
	}
	for _, origin := range policy.Origins {
		if origin == c.Origin {
			return nil
		}
	}
	return ErrDenied
}

type credentialInstaller interface {
	InstallCredential(context.Context, CookieCredential) error
}

func (w *Worker) putCredential(ctx context.Context, p Principal, secret CookieCredential) error {
	if w.Store == nil || secret.Validate(w.CredentialPolicy) != nil {
		return ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(p.Expires, 0))
	defer cancel()
	w.mu.Lock()
	defer func() {
		w.Store.releaseRead(w.Owner, "credential-write", p.ID)
		w.Store.releaseRead(w.Owner, "credential", "vault")
		w.mu.Unlock()
	}()
	if w.closed || ctx.Err() != nil || p.Owner != w.Owner || p.Audience != w.Audience || p.Scope != "credential.write" || p.Expires <= time.Now().Unix() {
		return ErrUnavailable
	}
	encoded, _ := json.Marshal(secret)
	digest := sha256.Sum256(encoded)
	hash := hex.EncodeToString(digest[:])
	record, e := w.Store.GetContext(ctx, w.Owner, "credential-write", p.ID)
	if e == nil {
		if string(record) == "complete:"+hash {
			return nil
		}
		if string(record) == "pending:"+hash {
			return ErrUncertain
		}
		return ErrDenied
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	secrets, err := w.credentials(ctx)
	if err != nil {
		return err
	}
	if _, exists := secrets[secret.Name]; !exists && len(secrets) >= 32 {
		return ErrCapacity
	}
	secrets[secret.Name] = secret
	data, err := json.Marshal(secrets)
	if err != nil {
		return ErrInvalid
	}
	if err = w.Store.CreateContext(ctx, w.Owner, "credential-write", p.ID, []byte("pending:"+hash)); err != nil {
		return err
	}
	if err = w.Store.PutContext(ctx, w.Owner, "credential", "vault", data); err != nil {
		return err
	}
	// Uncertain writes never replay an old credential over a later rotation.
	if w.driver != nil {
		installer, ok := w.driver.(credentialInstaller)
		if !ok {
			return ErrUnavailable
		}
		if err = installer.InstallCredential(ctx, secret); err != nil {
			return err
		}
	}
	return w.Store.PutContext(ctx, w.Owner, "credential-write", p.ID, []byte("complete:"+hash))
}

func (w *Worker) credentials(ctx context.Context) (map[string]CookieCredential, error) {
	data, err := w.Store.GetContext(ctx, w.Owner, "credential", "vault")
	if errors.Is(err, os.ErrNotExist) {
		return map[string]CookieCredential{}, nil
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	var secrets map[string]CookieCredential
	if json.Unmarshal(data, &secrets) != nil || len(secrets) > 32 {
		return nil, ErrDenied
	}
	for name, secret := range secrets {
		if name != secret.Name || secret.Validate(w.CredentialPolicy) != nil {
			return nil, ErrDenied
		}
	}
	return secrets, nil
}
