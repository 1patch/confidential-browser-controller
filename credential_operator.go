package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type CredentialTarget struct {
	Owner      string `json:"owner"`
	Audience   string `json:"audience"`
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
}

// Lookup is authorized by each owner's credential operator key. The application
// execution key cannot discover credential targets or mint credential authority.
func (c *Control) credentialTarget(w http.ResponseWriter, r *http.Request) {
	deny := func() { http.Error(w, `{"error":"denied"}`, http.StatusForbidden) }
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || len(token) > 2048 || len(parts) != 2 || c.Fleet == nil {
		deny()
		return
	}
	// This untrusted hint only selects a public key. No identity is accepted
	// until the signature, owner, audience, scope and expiration all verify.
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	var hint struct {
		Owner string `json:"owner"`
	}
	if err != nil || json.Unmarshal(body, &hint) != nil || !identifier.MatchString(hint.Owner) {
		deny()
		return
	}
	p, err := VerifyCapability(c.CredentialPublicKeys[hint.Owner], token, c.Audience, "credential.target", time.Now())
	if err != nil || p.Owner != hint.Owner || !c.AllowedOwners[p.Owner] {
		deny()
		return
	}
	body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 2))
	if err != nil || len(body) != 0 {
		deny()
		return
	}
	i, release, err := c.Fleet.Lease(p.Owner)
	if err != nil {
		http.Error(w, `{"error":"browser unavailable"}`, 503)
		return
	}
	defer release()
	if i.Owner != p.Owner || !identifier.MatchString(i.Name) || !enclaveDomain.MatchString(i.Domain) || !strings.HasPrefix(i.Domain, i.Name+".") || !releasePin.MatchString(i.Repository) {
		deny()
		return
	}
	json.NewEncoder(w).Encode(CredentialTarget{Owner: i.Owner, Audience: i.Name, Domain: i.Domain, Repository: i.Repository})
}

// CredentialOperatorConfig is private operator input, never a model tool's
// argument. Independent worker pinning prevents a target response changing code.
type CredentialOperatorConfig struct {
	ControllerDomain     string `json:"controllerDomain"`
	ControllerRepository string `json:"controllerRepository"`
	ControllerAudience   string `json:"controllerAudience"`
	WorkerRepository     string `json:"workerRepository"`
	Owner                string `json:"owner"`
}

func ParseCredentialOperatorConfig(raw []byte) (CredentialOperatorConfig, error) {
	var c CredentialOperatorConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 32<<10 || d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF ||
		!enclaveDomain.MatchString(c.ControllerDomain) || !releasePin.MatchString(c.ControllerRepository) ||
		!releasePin.MatchString(c.WorkerRepository) || !identifier.MatchString(c.ControllerAudience) || !identifier.MatchString(c.Owner) {
		return c, ErrInvalid
	}
	return c, nil
}

type CredentialOperator struct {
	Config  CredentialOperatorConfig
	Key     ed25519.PrivateKey
	connect func(string, string) (*http.Client, error) // tests only
}

// Install reads the secret only after both endpoints attest. It performs one
// write, with a caller-retained ID. A lost response never triggers a retry or a
// new request ID. Neither raw HTTP errors nor response bodies escape this API.
func (o CredentialOperator) Install(parent context.Context, id string, input io.Reader) error {
	raw, _ := json.Marshal(o.Config)
	if _, err := ParseCredentialOperatorConfig(raw); err != nil || !identifier.MatchString(id) || len(o.Key) != ed25519.PrivateKeySize || input == nil || parent.Err() != nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	connect := o.connect
	if connect == nil {
		connect = VerifiedHTTP
	}
	controller, err := connect(o.Config.ControllerDomain, o.Config.ControllerRepository)
	if err != nil || controller == nil {
		return ErrDenied
	}
	defer controller.CloseIdleConnections()
	p := Principal{Owner: o.Config.Owner, Audience: o.Config.ControllerAudience, Scope: "credential.target", ID: id, Expires: time.Now().Add(time.Minute).Unix()}
	body, err := o.post(ctx, controller, o.Config.ControllerDomain, "/v1/credential-target", p, nil)
	if err != nil {
		return err
	}
	var target CredentialTarget
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&target) != nil || d.Decode(new(any)) != io.EOF || target.Owner != o.Config.Owner ||
		!identifier.MatchString(target.Audience) || !enclaveDomain.MatchString(target.Domain) || !strings.HasPrefix(target.Domain, target.Audience+".") || target.Repository != o.Config.WorkerRepository {
		return ErrDenied
	}
	worker, err := connect(target.Domain, target.Repository)
	if err != nil || worker == nil || ctx.Err() != nil {
		return ErrDenied
	}
	defer worker.CloseIdleConnections()
	secret, err := io.ReadAll(io.LimitReader(input, (12<<10)+1))
	if err != nil || len(secret) == 0 || len(secret) > 12<<10 {
		clear(secret)
		return ErrInvalid
	}
	defer clear(secret)
	var credential CookieCredential
	d = json.NewDecoder(bytes.NewReader(secret))
	d.DisallowUnknownFields()
	if d.Decode(&credential) != nil || d.Decode(new(any)) != io.EOF || credential.Validate(NetworkPolicy{Origins: []string{credential.Origin}}) != nil {
		return ErrInvalid
	}
	p.Audience, p.Scope, p.Expires = target.Audience, "credential.write", time.Now().Add(time.Minute).Unix()
	body, err = o.post(ctx, worker, target.Domain, "/v1/credentials", p, secret)
	if err != nil {
		return ErrUncertain
	}
	var result struct {
		Stored bool `json:"stored"`
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || !result.Stored {
		return ErrUncertain
	}
	return nil
}

func (o CredentialOperator) post(ctx context.Context, client *http.Client, domain, path string, p Principal, body []byte) ([]byte, error) {
	token, err := SignCapability(o.Key, p)
	if err != nil || ctx.Err() != nil {
		return nil, ErrDenied
	}
	r, err := http.NewRequestWithContext(ctx, "POST", "https://"+domain+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return nil, ErrUncertain
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrUnavailable
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || len(result) > 2048 {
		return nil, ErrUncertain
	}
	return result, nil
}
