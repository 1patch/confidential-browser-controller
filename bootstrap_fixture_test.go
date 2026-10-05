package browser

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func testBootstrap(t *testing.T, owner string) Bootstrap {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	secretPub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	rand.Read(key)
	return Bootstrap{Version: 1, Owner: owner, Audience: "browser-instance", ExecutePublicKey: base64.StdEncoding.EncodeToString(pub), SecretsPublicKey: base64.StdEncoding.EncodeToString(secretPub), StorageKey: base64.StdEncoding.EncodeToString(key), Origins: []string{"https://example.com"}, CredentialOrigins: []string{"https://example.com"}, AllowWrites: true}
}
