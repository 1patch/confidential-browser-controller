package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type deniedPrepare struct{ calls int }

func (p *deniedPrepare) Prepare(context.Context, Instance) error {
	p.calls++
	return ErrDenied
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
