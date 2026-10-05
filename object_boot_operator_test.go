package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func bootOperator(t *testing.T, f *bootFixture) ObjectBootOperator {
	t.Helper()
	target := CredentialTarget{Owner: f.config.Browser.Owner, Audience: f.config.Browser.Audience,
		Domain: f.config.Browser.Audience + ".proof.containers.tinfoil.dev", Repository: "example/browser@v1@sha256:" + strings.Repeat("a", 64)}
	return ObjectBootOperator{Target: target, Key: f.key, connect: func(domain, pin string) (*http.Client, error) {
		if domain != target.Domain || pin != target.Repository {
			t.Fatal("operator changed attestation target")
		}
		return &http.Client{Transport: s3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Host != target.Domain || r.GetBody != nil {
				t.Fatal("unbound or replayable bootstrap transport")
			}
			out := httptest.NewRecorder()
			f.gate.ServeHTTP(out, r)
			return out.Result(), nil
		})}, nil
	}}
}

type bootInputProbe struct{ reads int }

func (p *bootInputProbe) Read([]byte) (int, error) { p.reads++; return 0, io.EOF }

func TestObjectBootOperatorAttestsBeforeReadingSecrets(t *testing.T) {
	f := newBootFixture(t, context.Background())
	o := bootOperator(t, f)
	o.connect = func(string, string) (*http.Client, error) { return nil, ErrDenied }
	probe := &bootInputProbe{}
	if _, err := o.Deliver(context.Background(), probe); err != ErrDenied || probe.reads != 0 || f.calls.Load() != 0 {
		t.Fatal("failed attestation read or sent secrets")
	}
	for _, mutate := range []func(*ObjectBootOperator){
		func(o *ObjectBootOperator) { o.Target.Domain = "other.proof.containers.tinfoil.dev" },
		func(o *ObjectBootOperator) { o.Target.Repository = "example/browser@main" },
		func(o *ObjectBootOperator) { o.Target.Owner = "../alice" },
		func(o *ObjectBootOperator) { o.Target.Domain += ":443" },
	} {
		o = bootOperator(t, f)
		o.connect = func(string, string) (*http.Client, error) {
			t.Fatal("invalid target reached attestation")
			return nil, ErrDenied
		}
		mutate(&o)
		if _, err := o.Deliver(context.Background(), probe); err == nil || probe.reads != 0 {
			t.Fatal("unbound target read secrets")
		}
	}
}

func TestObjectBootOperatorRequiresReservationBeforePost(t *testing.T) {
	for _, mode := range []string{"missing", "failed", "saved"} {
		t.Run(mode, func(t *testing.T) {
			f := newBootFixture(t, context.Background())
			o := bootOperator(t, f)
			var posts atomic.Int32
			var recorded ObjectBootStatus
			connect := o.connect
			o.connect = func(domain, pin string) (*http.Client, error) {
				client, err := connect(domain, pin)
				if err != nil {
					return nil, err
				}
				transport := client.Transport
				client.Transport = s3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method == http.MethodPost {
						if !validObjectBootStatus(recorded) || recorded.State != "starting" || recorded.Digest != objectBootDigest(f.raw) {
							t.Fatal("credentials sent before receipt reservation")
						}
						posts.Add(1)
					}
					return transport.RoundTrip(r)
				})
				return client, nil
			}
			var reserve func(ObjectBootStatus) error
			if mode != "missing" {
				reserve = func(status ObjectBootStatus) error {
					if mode == "failed" {
						return ErrUnavailable
					}
					recorded = status
					return nil
				}
			}
			_, err := o.DeliverRecorded(context.Background(), bytes.NewReader(f.raw), reserve)
			if mode == "saved" {
				if err != nil || posts.Load() != 1 {
					t.Fatal("recorded delivery failed", err)
				}
				awaitBoot(t, f.gate)
			} else if err == nil || posts.Load() != 0 || f.calls.Load() != 0 {
				t.Fatal("unreserved delivery reached the worker")
			}
		})
	}
}

func TestObjectBootOperatorLostAcknowledgmentRequiresReadOnlyResolution(t *testing.T) {
	f := newBootFixture(t, context.Background())
	o := bootOperator(t, f)
	connect := o.connect
	var posts atomic.Int32
	o.connect = func(domain, pin string) (*http.Client, error) {
		client, err := connect(domain, pin)
		if err != nil {
			return nil, err
		}
		transport := client.Transport
		client.Transport = s3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			response, err := transport.RoundTrip(r)
			if r.Method == http.MethodPost {
				posts.Add(1)
				if response != nil {
					response.Body.Close()
				}
				return nil, errors.New("synthetic lost acknowledgment")
			}
			return response, err
		})
		return client, nil
	}
	receipt, err := o.Deliver(context.Background(), bytes.NewReader(f.raw))
	if err != ErrUncertain || receipt.Digest != objectBootDigest(f.raw) || posts.Load() != 1 {
		t.Fatal("lost acknowledgment was replayed or lost receipt")
	}
	awaitBoot(t, f.gate)
	status, err := o.Inspect(context.Background(), receipt)
	if err != nil || status.State != "ready" || posts.Load() != 1 || f.calls.Load() != 1 {
		t.Fatal("read-only recovery failed", err)
	}
	probe := &bootInputProbe{}
	if _, err := o.Deliver(context.Background(), probe); err == nil || probe.reads != 0 || posts.Load() != 1 {
		t.Fatal("claimed boot prompted a second private submission")
	}
	for _, mutate := range []func(*ObjectBootStatus){
		func(s *ObjectBootStatus) { s.Nonce = strings.Repeat("A", 43) },
		func(s *ObjectBootStatus) { s.Digest = strings.Repeat("b", 64) },
	} {
		bad := receipt
		mutate(&bad)
		if _, err := o.Inspect(context.Background(), bad); err != ErrUncertain {
			t.Fatal("mismatched recovery receipt accepted")
		}
	}
}

func TestObjectBootOperatorBindsPrivateInputToRetainedOwner(t *testing.T) {
	for _, field := range []string{"owner", "audience", "issuer"} {
		t.Run(field, func(t *testing.T) {
			f := newBootFixture(t, context.Background())
			o := bootOperator(t, f)
			switch field {
			case "owner":
				f.config.Browser.Owner = "bob"
			case "audience":
				f.config.Browser.Audience = "other-instance"
			case "issuer":
				o.Key = f.exec
			}
			raw, _ := json.Marshal(f.config)
			if _, err := o.Deliver(context.Background(), bytes.NewReader(raw)); err != ErrDenied || f.calls.Load() != 0 {
				t.Fatal("wrong private authority reached worker", err)
			}
		})
	}
}

func TestObjectBootOperatorDeliversWithoutClaimingReadyEarly(t *testing.T) {
	f := newBootFixture(t, context.Background())
	o := bootOperator(t, f)
	receipt, err := o.Deliver(context.Background(), bytes.NewReader(f.raw))
	if err != nil || receipt.State != "starting" {
		t.Fatal("bootstrap claim confused with readiness", err)
	}
	awaitBoot(t, f.gate)
	status, err := o.Inspect(context.Background(), receipt)
	if err != nil || status.State != "ready" {
		t.Fatal("ready bootstrap unavailable", err)
	}
}
