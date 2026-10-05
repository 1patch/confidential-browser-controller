package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func syntheticStorageIssuer() StorageIssuerConfig {
	return StorageIssuerConfig{Authority: StorageIssuerAuthority{Region: "us-east-1", AccessKeyID: "SYNTHETICISSUERKEY", SecretAccessKey: strings.Repeat("synthetic", 5)}, Roles: map[string]StorageIssuerRole{
		"alice": {ARN: "arn:aws:iam::123456789012:role/browser/alice", Bucket: "browser-alice", Region: "us-east-1", ExternalID: "synthetic-external-id"},
		"bob":   {ARN: "arn:aws:iam::123456789012:role/browser/bob", Bucket: "browser-bob", Region: "us-east-1"},
	}}
}

func issuerResponse(r *http.Request, session, role string, expires time.Time) *http.Response {
	body := fmt.Sprintf(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>SYNTHETICISSUEDKEY</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>synthetic-issued-token</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/%s/%s</Arn><AssumedRoleId>synthetic-role-id</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, strings.Repeat("issued", 8), expires.UTC().Format(time.RFC3339), role, session)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func readIssuerRequest(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestStorageIssuerUsesPrivateAuthorityAndPinnedOwnerSessionPolicy(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_STS", "http://attacker.invalid")
	t.Setenv("AWS_ENDPOINT_URL", "http://attacker.invalid")
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-foreign-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-foreign-secret")
	config := syntheticStorageIssuer()
	expectedRole := config.Roles["alice"]
	sessions := map[string]bool{}
	posts := 0
	issuer, err := newAWSStorageIssuer(config, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		posts++
		if r.URL.String() != "https://sts.us-east-1.amazonaws.com/" || !strings.Contains(r.Header.Get("Authorization"), "Credential=SYNTHETICISSUERKEY/") {
			t.Fatal("authority or endpoint changed")
		}
		v := readIssuerRequest(t, r)
		if v.Get("Action") != "AssumeRole" || v.Get("Version") != "2011-06-15" || v.Get("DurationSeconds") != "3600" || len(v) != 7 {
			t.Fatal("unexpected issuance parameters")
		}
		session := v.Get("RoleSessionName")
		if !strings.HasPrefix(session, "browser-") || len(session) != 40 || sessions[session] || strings.Contains(session, "alice") {
			t.Fatal("session name is not a fresh opaque identifier")
		}
		sessions[session] = true
		if v.Get("RoleArn") != expectedRole.ARN || v.Get("ExternalId") != expectedRole.ExternalID {
			t.Fatal("role or external id was substituted")
		}
		var policy struct {
			Version   string
			Statement []struct {
				Effect   string
				Action   any
				Resource string
			}
		}
		if json.Unmarshal([]byte(v.Get("Policy")), &policy) != nil || policy.Version != "2012-10-17" || len(policy.Statement) != 2 {
			t.Fatal("missing session policy")
		}
		prefix, _ := S3OwnerPrefix("alice", "browser-proof")
		if policy.Statement[0].Effect != "Allow" || policy.Statement[0].Resource != "arn:aws:s3:::browser-alice/"+prefix+"*" || policy.Statement[1].Resource != "arn:aws:s3:::browser-alice" || policy.Statement[1].Action != "s3:ListBucket" {
			t.Fatal("session is not confined to the enrolled owner")
		}
		actions, _ := json.Marshal(policy.Statement[0].Action)
		if string(actions) != `["s3:GetObject","s3:PutObject"]` {
			t.Fatal("additional object permissions issued")
		}
		return issuerResponse(r, session, "alice", time.Now().Add(time.Hour)), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	// Constructor copies trusted enrollment; caller mutation cannot redirect it.
	config.Roles["alice"] = config.Roles["bob"]
	for range 2 {
		storage, err := issuer.Issue(context.Background(), "alice", "browser-proof")
		if err != nil || storage.Bucket != "browser-alice" || storage.Region != "us-east-1" || storage.AccessKeyID != "SYNTHETICISSUEDKEY" || storage.SessionToken == "" || !storageLeaseUsable(storage, time.Now()) {
			t.Fatal("valid issue failed", err)
		}
	}
	for _, binding := range [][2]string{{"foreign", "browser-proof"}, {"alice", "bad/audience"}} {
		if _, err := issuer.Issue(context.Background(), binding[0], binding[1]); err == nil {
			t.Fatal("unenrolled binding accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = issuer.Issue(ctx, "alice", "browser-proof"); err == nil || posts != 2 {
		t.Fatal("denied binding contacted the issuer")
	}
}

func TestStorageIssuerDeniesExpiredAuthorityWithoutAmbientFallback(t *testing.T) {
	c := syntheticStorageIssuer()
	c.Authority.SessionToken = "synthetic-expired-source"
	c.Authority.Expires = time.Now().Add(-time.Second).Unix()
	posts := 0
	i, err := newAWSStorageIssuer(c, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		posts++
		return nil, ErrUnavailable
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = i.Issue(context.Background(), "alice", "proof"); err == nil || posts != 0 {
		t.Fatal("expired issuer used network or ambient credentials")
	}
}

func TestStorageIssuerRejectsUnsafeEnrollment(t *testing.T) {
	for _, change := range []string{"region", "short-key", "token-expiry", "shared-role", "shared-bucket", "foreign-partition", "role-url", "empty-role-name", "external-id", "unknown-owner"} {
		t.Run(change, func(t *testing.T) {
			c := syntheticStorageIssuer()
			role := c.Roles["alice"]
			switch change {
			case "region":
				c.Authority.Region = "local"
			case "short-key":
				c.Authority.SecretAccessKey = "short"
			case "token-expiry":
				c.Authority.SessionToken = "unbounded-token"
			case "shared-role":
				role.ARN = c.Roles["bob"].ARN
			case "shared-bucket":
				role.Bucket = c.Roles["bob"].Bucket
			case "foreign-partition":
				role.ARN = "arn:aws-cn:iam::123456789012:role/alice"
			case "role-url":
				role.ARN = "https://attacker.invalid"
			case "empty-role-name":
				role.ARN = "arn:aws:iam::123456789012:role/"
			case "external-id":
				role.ExternalID = "bad value"
			case "unknown-owner":
				c.Roles["bad/owner"] = role
			}
			c.Roles["alice"] = role
			if _, err := NewAWSStorageIssuer(c); err == nil {
				t.Fatal("unsafe enrollment accepted")
			}
		})
	}
}

func TestStorageIssuerRejectsMalformedRepliesAndNeverRetriesOrLeaksErrors(t *testing.T) {
	for _, failure := range []string{"redirect", "server-error", "lost-reply", "foreign-role", "expired", "oversized-duration", "missing-token", "truncated", "oversized-response"} {
		t.Run(failure, func(t *testing.T) {
			posts := 0
			i, err := newAWSStorageIssuer(syntheticStorageIssuer(), &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				posts++
				v := readIssuerRequest(t, r)
				role, expires := "alice", time.Now().Add(time.Hour)
				if failure == "foreign-role" {
					role = "bob"
				}
				if failure == "expired" {
					expires = time.Now().Add(time.Minute)
				}
				if failure == "oversized-duration" {
					expires = time.Now().Add(3 * time.Hour)
				}
				resp := issuerResponse(r, v.Get("RoleSessionName"), role, expires)
				switch failure {
				case "redirect":
					resp.StatusCode = 307
					resp.Header.Set("Location", "https://attacker.invalid/")
				case "server-error":
					resp.StatusCode = 500
					resp.Body = io.NopCloser(strings.NewReader(`<ErrorResponse><Error><Code>InternalFailure</Code><Message>synthetic-private-issuer-details</Message></Error></ErrorResponse>`))
				case "lost-reply":
					return nil, fmt.Errorf("synthetic-private-issuer-details")
				case "missing-token":
					raw, _ := io.ReadAll(resp.Body)
					resp.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(raw), "synthetic-issued-token", "")))
				case "truncated":
					resp.Body = io.NopCloser(strings.NewReader(`<AssumeRoleResponse>`))
				case "oversized-response":
					resp.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", 65<<10)))
				}
				return resp, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			value, err := i.Issue(context.Background(), "alice", "proof")
			if err == nil || value != (S3StoreConfig{}) || posts != 1 || strings.Contains(err.Error(), "synthetic-private") {
				t.Fatal("unsafe reply accepted, retried or exposed private error", posts)
			}
		})
	}
}
