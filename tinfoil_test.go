package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type deniedPrepare struct{ calls int }

func (p *deniedPrepare) Prepare(context.Context, Instance) error {
	p.calls++
	return ErrDenied
}

func TestBrowserBootstrapReadinessWaitsOnlyForReadOnlyAvailability(t *testing.T) {
	domain, pin := "browser-proof.proof.containers.tinfoil.dev", "example/browser@v1@sha256:"+strings.Repeat("a", 64)
	for _, scenario := range []string{"transient-fetch", "transient-upstream", "bad-evidence", "unexpected-status", "channel-failure", "canceled", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			calls, reads := 0, 0
			connect := func(gotDomain, gotPin string) (*http.Client, error) {
				calls++
				if gotDomain != domain || gotPin != pin {
					t.Fatal("readiness changed attestation identity")
				}
				if scenario == "bad-evidence" {
					return nil, ErrDenied
				}
				if scenario == "transient-fetch" && calls == 1 || scenario == "deadline" {
					return nil, ErrUnavailable
				}
				if scenario == "canceled" {
					cancel()
				}
				return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					reads++
					if r.Method != "GET" || r.URL.String() != "https://"+domain+"/v1/bootstrap" || r.Header.Get("Authorization") != "" || r.Body != nil {
						t.Fatal("readiness submitted authority or an effect")
					}
					if scenario == "channel-failure" {
						return nil, ErrDenied
					}
					status := http.StatusOK
					if scenario == "transient-upstream" && calls == 1 {
						status = http.StatusServiceUnavailable
					}
					if scenario == "unexpected-status" {
						status = http.StatusNotFound
					}
					return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"state":"waiting"}`))}, nil
				})}, nil
			}
			err := waitBrowserBootstrap(ctx, domain, pin, connect, time.Millisecond)
			switch scenario {
			case "transient-fetch", "transient-upstream":
				if err != nil || calls != 2 || reads < 1 {
					t.Fatal("transient startup did not recover", err, calls, reads)
				}
			case "deadline":
				if err != ErrUnavailable || reads != 0 {
					t.Fatal("availability wait escaped deadline", err)
				}
			case "canceled":
				if err != ErrUnavailable || calls != 1 || reads != 0 {
					t.Fatal("canceled verification continued", err, calls, reads)
				}
			default:
				if err != ErrDenied || calls != 1 {
					t.Fatal("invalid evidence or channel was retried", err, calls)
				}
			}
		})
	}
}

func TestTinfoilObservedVariablesAndStartedState(t *testing.T) {
	encoded := func(value string) string {
		raw, _ := json.Marshal(base64.StdEncoding.EncodeToString([]byte(value)))
		return string(raw)
	}
	for _, test := range []struct {
		name, variables string
		allowed         bool
	}{
		{"object", `{}`, true},
		{"null", `null`, true},
		{"jsonb", encoded(`{}`), true},
		{"jsonb-space", encoded(" { }\n"), true},
		{"nonempty", `{"OVERRIDE":"value"}`, false},
		{"jsonb-nonempty", encoded(`{"OVERRIDE":"value"}`), false},
		{"array", `[]`, false},
		{"jsonb-array", encoded(`[]`), false},
		{"jsonb-null", encoded(`null`), false},
		{"nested-encoding", encoded(`"e30="`), false},
		{"unpadded", `"e30"`, false},
		{"noncanonical", `"e31="`, false},
		{"not-base64", `"{}"`, false},
		{"multiple-json", encoded(`{} {}`), false},
		{"oversized", encoded(strings.Repeat(" ", 257) + "{}"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepare := &deniedPrepare{}
			p := &TinfoilProvider{AdminKey: "admin_synthetic", Repository: "example/browser@v1@sha256:" + strings.Repeat("a", 64), DomainSuffix: "proof.containers.tinfoil.dev", Provisioner: prepare}
			i := Instance{Owner: "alice", ID: "00000000-0000-0000-0000-000000000001", Name: "browser-aaaaaaaaaaaaaaaaaaaaaaaa", Domain: "browser-aaaaaaaaaaaaaaaaaaaaaaaa.proof.containers.tinfoil.dev", Repository: p.Repository}
			reads, writes := 0, 0
			p.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" {
					writes++
					return nil, ErrDenied
				}
				if r.URL.Host != "api.tinfoil.sh" || r.URL.Path != "/api/containers/"+i.ID || r.Header.Get("Authorization") != "Bearer admin_synthetic" {
					t.Fatal("unexpected cloud destination")
				}
				reads++
				state := "started"
				if reads > 1 {
					state = "running"
				}
				raw, err := json.Marshal(containerStatus{ID: i.ID, Name: i.Name, Domain: i.Domain, Repo: "example/browser", Tag: "v1", Status: state, CPUs: 2, Memory: 8192, Variables: json.RawMessage(test.variables)})
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}
			err := p.Start(context.Background(), i)
			if (err == nil) != test.allowed || writes != 0 || prepare.calls != 0 {
				t.Fatal("unexpected activation or mutation", err, writes, prepare.calls)
			}
			if test.allowed && reads != 2 || !test.allowed && reads != 1 {
				t.Fatal("unexpected polling after policy decision", reads)
			}
		})
	}
}
