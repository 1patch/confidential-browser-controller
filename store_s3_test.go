package browser

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type s3RoundTripFunc func(*http.Request) (*http.Response, error)

func (f s3RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func syntheticS3Config() S3StoreConfig {
	return S3StoreConfig{Bucket: "browser-proof", Region: "us-east-1", AccessKeyID: "SYNTHETICACCESSKEY", SecretAccessKey: strings.Repeat("synthetic", 5), SessionToken: "synthetic-session", Expires: time.Now().Add(time.Hour).Unix()}
}
func s3Response(req *http.Request, status int, body, version string) *http.Response {
	return &http.Response{StatusCode: status, Request: req, Header: http.Header{"Etag": []string{version}, "Content-Type": []string{"application/xml"}, "Content-Length": []string{strconv.Itoa(len(body))}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestS3BackendUsesSignedBoundedConditionalRequests(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_S3", "http://attacker.invalid")
	t.Setenv("AWS_ACCESS_KEY_ID", "foreign-ambient-key")
	cfg := syntheticS3Config()
	prefix, _ := S3OwnerPrefix("alice", "worker")
	step := 0
	client := &http.Client{Transport: s3RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		step++
		if req.URL.Scheme != "https" || req.URL.Host != "s3.us-east-1.amazonaws.com" || req.URL.Path != "/browser-proof/"+prefix+"identity.sealed" {
			t.Fatal("storage endpoint or owner namespace changed")
		}
		if !strings.Contains(req.Header.Get("Authorization"), "Credential="+cfg.AccessKeyID+"/") || req.Header.Get("X-Amz-Security-Token") != cfg.SessionToken {
			t.Fatal("SDK did not use the explicit private bootstrap")
		}
		switch step {
		case 1:
			if req.Method != "GET" {
				t.Fatal("expected GET")
			}
			return s3Response(req, 404, `<Error><Code>NoSuchKey</Code></Error>`, ""), nil
		case 2:
			data, _ := io.ReadAll(req.Body)
			if req.Method != "PUT" || req.Header.Get("If-None-Match") != "*" || req.Header.Get("If-Match") != "" || string(data) != "ciphertext" {
				t.Fatal("initial put lacked exclusive creation")
			}
			return s3Response(req, 200, "", `"version1"`), nil
		case 3:
			if req.Method != "PUT" || req.Header.Get("If-Match") != `"version1"` || req.Header.Get("If-None-Match") != "" {
				t.Fatal("update lacked its observed version")
			}
			return s3Response(req, 200, "", `"version2"`), nil
		case 4:
			return s3Response(req, 200, "ciphertext", `"version2"`), nil
		default:
			t.Fatal("unexpected retry")
		}
		return nil, ErrDenied
	})}
	b, err := newS3BlobBackend(cfg, "alice", "worker", client)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err = b.Get(ctx, "identity.sealed"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing object not classified", err)
	}
	v, err := b.Put(ctx, "identity.sealed", []byte("ciphertext"), "")
	if err != nil || v != `"version1"` {
		t.Fatal("create", err)
	}
	v, err = b.Put(ctx, "identity.sealed", []byte("ciphertext"), v)
	if err != nil || v != `"version2"` {
		t.Fatal("update", err)
	}
	got, v, err := b.Get(ctx, "identity.sealed")
	if err != nil || string(got) != "ciphertext" || v != `"version2"` || step != 4 {
		t.Fatal("read", err, step)
	}
	for _, key := range []string{"../identity.sealed", "foreign/identity.sealed", "identity.sealed?x=1", "credential"} {
		if _, _, err = b.Get(ctx, key); err == nil {
			t.Fatal("invalid object accepted")
		}
	}
	if _, err = b.Put(ctx, "identity.sealed", []byte("ciphertext"), "malformed"); err == nil || step != 4 {
		t.Fatal("invalid version reached S3")
	}
}

func TestS3BackendDoesNotRetryOrFollowRedirects(t *testing.T) {
	for _, status := range []int{301, 307, 403, 409, 412, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: s3RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				response := s3Response(req, status, `<Error><Code>SlowDown</Code></Error>`, "")
				response.Header.Set("Location", "https://attacker.invalid/storage")
				return response, nil
			})}
			b, err := newS3BlobBackend(syntheticS3Config(), "alice", "worker", client)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.Put(context.Background(), "identity.sealed", []byte("ciphertext"), ""); !errors.Is(err, ErrUncertain) || calls != 1 {
				t.Fatal("mutation retried or error leaked", err, calls)
			}
		})
	}
}

func TestS3BackendRejectsUnboundedAndUnversionedReads(t *testing.T) {
	for _, mode := range []string{"huge", "truncated", "versionless", "wrong-error"} {
		t.Run(mode, func(t *testing.T) {
			client := &http.Client{Transport: s3RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				response := s3Response(req, 200, "ciphertext", `"v1"`)
				switch mode {
				case "huge":
					response.ContentLength = 64 << 20
					response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
				case "truncated":
					response.ContentLength = 1024
					response.Header.Set("Content-Length", "1024")
				case "versionless":
					response.Header.Del("Etag")
				case "wrong-error":
					response = s3Response(req, 404, `<Error><Code>NoSuchBucket</Code></Error>`, "")
				}
				return response, nil
			})}
			b, err := newS3BlobBackend(syntheticS3Config(), "alice", "worker", client)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = b.Get(context.Background(), "identity.sealed"); err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe response treated as valid or absent", err)
			}
		})
	}
	client, err := newS3BlobBackend(syntheticS3Config(), "alice", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.client.Options().HTTPClient.(*http.Client).Transport.(s3OnlyTransport)
	if transport.inner.(*http.Transport).Proxy != nil {
		t.Fatal("storage inherited a proxy")
	}
	for _, url := range []string{"http://s3.us-east-1.amazonaws.com", "https://attacker.invalid", "https://user@s3.us-east-1.amazonaws.com", "https://s3.us-east-1.amazonaws.com:443"} {
		req, _ := http.NewRequest("GET", url, nil)
		if _, err = transport.RoundTrip(req); err == nil {
			t.Fatal("foreign transport endpoint accepted")
		}
	}
}
