package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	secureclient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

var releasePin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}@[A-Za-z0-9_.-]+@sha256:[a-f0-9]{64}$`)
var instanceID = regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
var enclaveDomain = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9-]+\.containers\.tinfoil\.dev$`)

// Matches the measured CPU-only startup window used by the application's
// confidential Bash provider. Preparation adds one minute around provisioning.
const BrowserStartupTimeout = 11 * time.Minute

// Matches the existing Bash adapter's confirmed shutdown allowance.
const BrowserStopTimeout = 3 * time.Minute

// VerifiedHTTP uses an immutable release pin and attested TLS. Authentication
// headers and bodies both terminate at the verified enclave, with no fallback.
func VerifiedHTTP(domain, pin string) (*http.Client, error) {
	if !enclaveDomain.MatchString(domain) || !releasePin.MatchString(pin) {
		return nil, ErrInvalid
	}
	// Use the vendor's TLS verifier directly; its top-level package also embeds
	// the unrelated OpenAI inference SDK. Preserve exact-origin binding here.
	secure, err := secureclient.NewSecureClient(domain, pin, nil)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err = secure.Verify(); err != nil {
		return nil, ErrDenied
	}
	client, err := secure.HTTPClient()
	if err != nil {
		return nil, ErrDenied
	}
	client.Transport = enclaveTransport{domain: domain, inner: client.Transport}
	client.Timeout = 45 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrDenied }
	return client, nil
}

type enclaveTransport struct {
	domain string
	inner  http.RoundTripper
}

func (t enclaveTransport) CloseIdleConnections() {
	if closer, ok := t.inner.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t enclaveTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || r.URL.Scheme != "https" || r.URL.Host != t.domain || (r.Host != "" && r.Host != t.domain) || r.URL.User != nil || r.URL.Opaque != "" {
		return nil, ErrDenied
	}
	return t.inner.RoundTrip(r)
}

// PrivateProvisioner prepares owner-bound encrypted persistence. Volume mode
// attaches a disk and authorizes the private keyserver; object mode uses the
// additional attested lifecycle below. It receives no model input. An absent
// provisioner fails closed; a managed-secret shortcut is forbidden.
type PrivateProvisioner interface {
	Prepare(context.Context, Instance) error
}

// Object persistence needs an attested bootstrap after the VM starts and a
// closed checkpoint before a stopped VM can be considered safe to wake again.
// The existing managed-volume provisioner does not implement these hooks.
type objectWorkerLifecycle interface {
	activate(context.Context, Instance) error
	verifyBoot(context.Context, Instance) error
	drain(context.Context, Instance) error
	checkpointed(context.Context, Instance) error
}

type TinfoilProvider struct {
	AdminKey     string
	Repository   string
	DomainSuffix string
	Provisioner  PrivateProvisioner
	client       *http.Client
	baseURL      string                                     // package-private test transport only
	connect      func(string, string) (*http.Client, error) // same-package tests only
}

type containerStatus struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Domain      string          `json:"domain"`
	Repo        string          `json:"repo"`
	Tag         string          `json:"current_tag"`
	Status      string          `json:"status"`
	Debug       bool            `json:"debug"`
	CPUs        int             `json:"cpus"`
	Memory      int             `json:"memory_mb"`
	GPUs        int             `json:"gpus"`
	HostID      string          `json:"host_id"`
	DisableCC   bool            `json:"disable_cc_mode"`
	SSHKeys     []string        `json:"ssh_keys"`
	Secrets     []string        `json:"secrets"`
	Variables   json.RawMessage `json:"variables"`
	VolumeSlots []struct {
		Name      string `json:"name"`
		KeySecret string `json:"key_secret"`
	} `json:"volume_slots"`
	Volumes map[string]string `json:"volumes"`
}

// Tinfoil's JSONB field may arrive as an object or canonical base64 JSON.
// Decode only the bounded observed encoding; neither form permits variables.
func emptyContainerVariables(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return true
	}
	if raw[0] == '"' {
		var encoded string
		if json.Unmarshal(raw, &encoded) != nil || len(encoded) > 256 {
			return false
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
			return false
		}
		raw = decoded
	}
	var values map[string]json.RawMessage
	return json.Unmarshal(raw, &values) == nil && values != nil && len(values) == 0
}

func (p *TinfoilProvider) api(ctx context.Context, method, path string, body any, out any) error {
	if !strings.HasPrefix(p.AdminKey, "admin_") || !releasePin.MatchString(p.Repository) || p.Provisioner == nil {
		return ErrDenied
	}
	data, err := json.Marshal(body)
	if err != nil {
		return ErrInvalid
	}
	base := p.baseURL
	if base == "" {
		base = "https://api.tinfoil.sh"
	}
	if !strings.HasPrefix(path, "/api/") {
		path = "/api/containers" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("Authorization", "Bearer "+p.AdminKey)
	req.Header.Set("Content-Type", "application/json")
	client := p.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ErrUncertain
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ErrUnavailable
	}
	if out != nil && json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out) != nil {
		return ErrUncertain
	}
	return nil
}

func (p *TinfoilProvider) identity(v containerStatus, i Instance, policy bool) error {
	parts := strings.Split(p.Repository, "@")
	if len(parts) != 3 || !instanceID.MatchString(v.ID) || v.ID != i.ID || v.Name != i.Name || v.Domain != i.Domain || v.Domain != v.Name+"."+p.DomainSuffix || !enclaveDomain.MatchString(v.Domain) || v.Repo != parts[0] || i.Repository != p.Repository {
		return ErrDenied
	}
	if policy && (v.Debug || v.DisableCC || len(v.SSHKeys) > 0 || len(v.Secrets) > 0 || !emptyContainerVariables(v.Variables) || v.Tag != parts[1] || v.CPUs != 2 || v.Memory != 8192 || v.GPUs != 0) {
		return ErrDenied
	}
	return nil
}

func (p *TinfoilProvider) get(ctx context.Context, i Instance, policy bool) (containerStatus, error) {
	var v containerStatus
	if !instanceID.MatchString(i.ID) {
		return v, ErrDenied
	}
	if err := p.api(ctx, "GET", "/"+i.ID, nil, &v); err != nil {
		return v, err
	}
	return v, p.identity(v, i, policy)
}

func (p *TinfoilProvider) Create(ctx context.Context, owner, name string) (Instance, error) {
	if !identifier.MatchString(owner) || !regexp.MustCompile(`^browser-[a-f0-9]{24}$`).MatchString(name) || !releasePin.MatchString(p.Repository) {
		return Instance{}, ErrInvalid
	}
	parts := strings.Split(p.Repository, "@")
	var v containerStatus
	err := p.api(ctx, "POST", "", map[string]any{"name": name, "repo": parts[0], "tag": parts[1], "debug": false, "secrets": []string{}, "variables": map[string]string{}, "ssh_keys": []string{}, "mark_latest_release": false}, &v)
	i := Instance{Owner: owner, ID: v.ID, Name: name, Domain: v.Domain, Repository: p.Repository}
	if err != nil {
		return i, err
	}
	if p.identity(v, i, false) != nil {
		return i, ErrDenied
	}
	return i, nil
}

func (p *TinfoilProvider) Start(ctx context.Context, i Instance) error {
	v, err := p.get(ctx, i, true)
	if err != nil {
		return err
	}
	if v.Status == "running" {
		return p.activate(ctx, i)
	}
	if v.Status == "stopped" {
		if err = p.Provisioner.Prepare(ctx, i); err != nil {
			return ErrDenied
		}
		if err = p.api(ctx, "POST", "/"+i.ID+"/deploy", map[string]any{"debug": false, "secrets": []string{}, "variables": map[string]string{}}, nil); err != nil {
			return err
		}
	} else if v.Status != "deploying" && v.Status != "pending" && v.Status != "started" {
		return ErrDenied
	}
	if err = p.wait(ctx, i, "running", true); err != nil {
		return err
	}
	return p.activate(ctx, i)
}

func (p *TinfoilProvider) activate(ctx context.Context, i Instance) error {
	if lifecycle, ok := p.Provisioner.(objectWorkerLifecycle); ok {
		return lifecycle.activate(ctx, i)
	}
	return nil
}

func (p *TinfoilProvider) Stop(ctx context.Context, i Instance) error {
	limit := BrowserStopTimeout
	lifecycle, objectMode := p.Provisioner.(objectWorkerLifecycle)
	if objectMode {
		limit += 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	v, err := p.get(ctx, i, false)
	if err != nil {
		return err
	}
	if v.Status == "stopped" {
		return p.checkpointed(ctx, i)
	}
	if objectMode && v.Status != "stopping" {
		if err = lifecycle.drain(ctx, i); err != nil {
			return err
		}
	}
	// Stop confirmation is authoritative even if its acknowledgment was lost.
	if v.Status != "stopping" {
		_ = p.api(ctx, "POST", "/"+i.ID+"/stop", map[string]any{}, nil)
	}
	if err = p.wait(ctx, i, "stopped", false); err != nil {
		return err
	}
	return p.checkpointed(ctx, i)
}

func (p *TinfoilProvider) checkpointed(ctx context.Context, i Instance) error {
	if lifecycle, ok := p.Provisioner.(objectWorkerLifecycle); ok {
		return lifecycle.checkpointed(ctx, i)
	}
	return nil
}

func (p *TinfoilProvider) wait(parent context.Context, i Instance, state string, policy bool) error {
	ctx, cancel := context.WithTimeout(parent, BrowserStartupTimeout)
	defer cancel()
	for {
		v, err := p.get(ctx, i, policy)
		if err != nil {
			return err
		}
		if v.Status == state {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrUncertain
		case <-timer.C:
		}
	}
}

func (p *TinfoilProvider) Verify(ctx context.Context, i Instance) error {
	v, err := p.get(ctx, i, true)
	if err != nil || v.Status != "running" {
		return ErrDenied
	}
	if lifecycle, ok := p.Provisioner.(objectWorkerLifecycle); ok {
		if err = lifecycle.verifyBoot(ctx, i); err != nil {
			return err
		}
	}
	connect := p.connect
	if connect == nil {
		connect = VerifiedHTTP
	}
	client, err := connect(i.Domain, i.Repository)
	if err != nil {
		return ErrDenied
	}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+i.Domain+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ErrDenied
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ErrUnavailable
	}
	return nil
}
