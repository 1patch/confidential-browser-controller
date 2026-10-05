package browser

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

func SignCapability(key ed25519.PrivateKey, p Principal) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrInvalid
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalid
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(key, []byte("sure-browser/v1."+encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyCapability(key ed25519.PublicKey, token, audience, scope string, now time.Time) (Principal, error) {
	var p Principal
	if len(key) != ed25519.PublicKeySize || len(token) > 2048 {
		return p, ErrDenied
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return p, ErrDenied
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(key, []byte("sure-browser/v1."+parts[0]), sig) {
		return p, ErrDenied
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(body, &p) != nil {
		return Principal{}, ErrDenied
	}
	if !identifier.MatchString(p.Owner) || !identifier.MatchString(p.ID) || p.Audience != audience || p.Scope != scope || p.Expires <= now.Unix() || p.Expires > now.Add(2*time.Minute).Unix() {
		return Principal{}, ErrDenied
	}
	return p, nil
}
