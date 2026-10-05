package browser

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingDriver struct{ actions []Action }

func (*recordingDriver) CurrentURL(context.Context, string) (string, error) {
	return "https://example.com", nil
}

func (d *recordingDriver) Do(_ context.Context, a Action) (Observation, error) {
	d.actions = append(d.actions, a)
	return Observation{URL: "https://example.com", Text: "synthetic-page"}, nil
}
func (*recordingDriver) Close(context.Context) error { return nil }

func TestWASMDrivesBroker(t *testing.T) {
	d := &recordingDriver{}
	s := Sandbox{Safety: StubSafety{Policy: NetworkPolicy{[]string{"https://example.com"}}, AllowWrites: true}}
	result, err := s.Execute(context.Background(), "alice", `await browser.navigate({url:"https://example.com"}); for(let i=0;i<3;i++) await browser.click({selector:"button"}); return (await browser.snapshot()).text;`, d)
	if err != nil || string(result.Value) != `"synthetic-page"` || len(d.actions) != 5 {
		t.Fatalf("run: %+v %v effects=%d", result, err, len(d.actions))
	}
}

func TestWASMCannotAccessHostOrBrowserSecrets(t *testing.T) {
	t.Setenv("SURE_TEST_SECRET", "sentinel-never-export")
	for _, code := range []string{
		`return typeof process+":"+typeof require+":"+typeof fetch+":"+typeof WebSocket;`,
		`return Object.keys(browser).join(",");`,
		`return std.getenv("SURE_TEST_SECRET");`,
		`return std.loadFile("/etc/passwd");`,
		`return std.loadFile("../../../../etc/passwd");`,
		`const f=std.open("escape","w"); return f===null;`,
		`const mod=await import("qjs:std"); return mod.loadFile("/etc/passwd");`,
	} {
		d := &recordingDriver{}
		result, err := (Sandbox{Safety: StubSafety{}}).Execute(context.Background(), "alice", code, d)
		if len(d.actions) != 0 || strings.Contains(string(result.Value), "sentinel-never-export") || strings.Contains(string(result.Value), "root:") {
			t.Fatalf("host leak: %s", code)
		}
		if strings.Contains(code, "typeof process") && (err != nil || string(result.Value) != `"undefined:undefined:undefined:undefined"`) {
			t.Fatal("baseline JS probe failed", err)
		}
		if strings.Contains(code, `std.open`) && err == nil && string(result.Value) != `true` {
			t.Fatal("filesystem write unexpectedly accessible", string(result.Value))
		}
		t.Logf("probe %q -> value=%s denied=%v", code, result.Value, err != nil)
	}
}

func TestWASMDeniesCapabilitiesAndEffectsBeforeSyntaxValidation(t *testing.T) {
	for _, code := range []string{
		`await browser.navigate({url:"https://example.com"}); ???`,
		`await browser.navigate({url:"file:///etc/passwd"});`,
		`await browser.navigate({url:"https://other.example"});`,
		`return browser.cookies();`, `return browser.exportSession();`, `return browser.restoreSession({});`,
		`return __browserAction('{"op":"exportSession"}');`, `return browser.evaluate("document.cookie");`,
		`return __browserAction('{"op":"cookies"}');`,
		`return browser.fill({selector:"input",text:"write"});`,
	} {
		d := &recordingDriver{}
		_, err := (Sandbox{Safety: StubSafety{Policy: NetworkPolicy{[]string{"https://example.com"}}}}).Execute(context.Background(), "alice", code, d)
		if err == nil || len(d.actions) != 0 {
			t.Fatalf("allowed %q: %v effects=%d", code, err, len(d.actions))
		}
	}
}

func TestWASMBoundsAndFreshHeaps(t *testing.T) {
	s := Sandbox{Safety: StubSafety{}, Timeout: 150 * time.Millisecond}
	start := time.Now()
	if _, err := s.Execute(context.Background(), "alice", `while(true){}`, &recordingDriver{}); err == nil {
		t.Fatal("loop allowed")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("deadline not enforced")
	}
	s.Timeout = 3 * time.Second
	if _, err := s.Execute(context.Background(), "alice", `globalThis.privateData="one"; return 1;`, &recordingDriver{}); err != nil {
		t.Fatal(err)
	}
	result, err := s.Execute(context.Background(), "bob", `return typeof privateData;`, &recordingDriver{})
	if err != nil || string(result.Value) != `"undefined"` {
		t.Fatal("heap crossed users", err)
	}
	d := &recordingDriver{}
	_, err = s.Execute(context.Background(), "alice", `for(let i=0;i<1000;i++) browser.snapshot();`, d)
	if err == nil || len(d.actions) != MaxActions {
		t.Fatal("action budget", len(d.actions), err)
	}
	_, err = s.Execute(context.Background(), "alice", `return "x".repeat(300000);`, &recordingDriver{})
	if err == nil {
		t.Fatal("output budget")
	}
}

type permissiveClassifier struct{}

func (permissiveClassifier) Program(context.Context, string, string) Decision {
	return Decision{Allow: true, Policy: "synthetic-allow"}
}
func (permissiveClassifier) Action(context.Context, ActionContext) Decision {
	return Decision{Allow: true, Policy: "synthetic-allow"}
}

func TestClassifierCannotExpandActionBudget(t *testing.T) {
	driver := &recordingDriver{}
	_, err := (Sandbox{Safety: permissiveClassifier{}}).Execute(context.Background(), "alice", `for(let i=0;i<1000;i++) browser.snapshot();`, driver)
	if err == nil || len(driver.actions) != MaxActions {
		t.Fatal("classifier expanded hard action limit", err, len(driver.actions))
	}
}

func TestEncryptedStoreIsolationAndTamper(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := NewSealedStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("synthetic-sentinel-never-plaintext")
	if err = s.Put("alice", "credential", "site", secret); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(dir)
	raw, _ := os.ReadFile(filepath.Join(dir, files[0].Name()))
	if strings.Contains(string(raw), string(secret)) {
		t.Fatal("plaintext at rest")
	}
	if _, err = s.Get("bob", "credential", "site"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cross-owner read", err)
	}
	_, other, _, _ := s.binding("bob", "credential", "site")
	os.WriteFile(other, raw, 0600)
	if _, err = s.Get("bob", "credential", "site"); err == nil {
		t.Fatal("ciphertext substituted across owners")
	}
	_, other, _, _ = s.binding("alice", "profile", "site")
	os.WriteFile(other, raw, 0600)
	if _, err = s.Get("alice", "profile", "site"); err == nil {
		t.Fatal("ciphertext substituted across purposes")
	}
	s2, _ := NewSealedStore(dir, key)
	plain, err := s2.Get("alice", "credential", "site")
	if err != nil || string(plain) != string(secret) {
		t.Fatal("restart", err)
	}
	raw[len(raw)-1] ^= 1
	_, original, _, _ := s.binding("alice", "credential", "site")
	os.WriteFile(original, raw, 0600)
	if _, err = s.Get("alice", "credential", "site"); err == nil {
		t.Fatal("tamper accepted")
	}
}

func TestCapabilitiesBindOwnerAudienceScopeAndTime(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := Principal{Owner: "alice", Audience: "worker-one", Scope: "execute", ID: "request-one", Expires: now.Add(time.Minute).Unix()}
	token, _ := SignCapability(priv, p)
	got, err := VerifyCapability(pub, token, p.Audience, p.Scope, now)
	if err != nil || got.Owner != "alice" {
		t.Fatal(err)
	}
	for _, args := range [][2]string{{"worker-two", "execute"}, {"worker-one", "secret.write"}} {
		if _, err = VerifyCapability(pub, token, args[0], args[1], now); err == nil {
			t.Fatal("scope bypass")
		}
	}
	if _, err = VerifyCapability(pub, token, p.Audience, p.Scope, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired accepted")
	}
	if _, err = VerifyCapability(pub, "x"+token, p.Audience, p.Scope, now); err == nil {
		t.Fatal("tampered accepted")
	}
}
