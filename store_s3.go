package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// S3StoreConfig is trusted private bootstrap, never agent tool input. Credentials
// must be scoped to this owner's prefix; no environment/default credential chain
// is used. Only ciphertext crosses the enclave boundary.
type S3StoreConfig struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
	Expires         int64  `json:"expires,omitempty"`
}

var s3Bucket = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
var s3Region = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9]$`)
var sealedObject = regexp.MustCompile(`^(identity|[a-f0-9]{64})\.sealed$`)
var s3Version = regexp.MustCompile(`^"[A-Za-z0-9-]{1,100}"$`)

type s3BlobBackend struct {
	client         *s3.Client
	bucket, prefix string
}

// S3OwnerPrefix lets the trusted provisioner scope an IAM policy before releasing
// credentials. Neither a request body nor an S3 caller-supplied prefix can select
// another user's namespace.
func S3OwnerPrefix(owner, audience string) (string, error) {
	if !identifier.MatchString(owner) || !identifier.MatchString(audience) {
		return "", ErrInvalid
	}
	bound := sha256.Sum256([]byte("browser-storage/v1\x00" + owner + "\x00" + audience))
	return "browser/v1/" + hex.EncodeToString(bound[:]) + "/", nil
}

// NewS3SealedStore reopens existing state. initialize must be true only in trusted
// provisioning, before boot; workers must fail if the fixed identity is missing.
// S3 is trusted for availability and version freshness, never for confidentiality.
func NewS3SealedStore(ctx context.Context, config S3StoreConfig, owner, audience string, key []byte, initialize bool) (*SealedStore, error) {
	backend, err := newS3BlobBackend(config, owner, audience, nil)
	if err != nil {
		return nil, err
	}
	return newRemoteSealedStore(ctx, owner, audience, key, backend, initialize)
}

func newS3BlobBackend(c S3StoreConfig, owner, audience string, testHTTP *http.Client) (*s3BlobBackend, error) {
	prefix, err := S3OwnerPrefix(owner, audience)
	if err != nil || !s3Bucket.MatchString(c.Bucket) || strings.HasSuffix(c.Bucket, "--x-s3") || !s3Region.MatchString(c.Region) || strings.HasPrefix(c.Region, "cn-") ||
		len(c.AccessKeyID) < 16 || len(c.AccessKeyID) > 128 || len(c.SecretAccessKey) < 32 || len(c.SecretAccessKey) > 256 || len(c.SessionToken) > 16<<10 ||
		strings.ContainsAny(c.AccessKeyID+c.SecretAccessKey+c.SessionToken, " \t\r\n\x00") ||
		(c.SessionToken == "" && c.Expires != 0) || (c.SessionToken != "" && (c.Expires <= 0 || c.Expires > 253402300799)) {
		return nil, ErrInvalid
	}
	host := "s3." + c.Region + ".amazonaws.com"
	httpClient := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
	}}
	if testHTTP != nil {
		httpClient = testHTTP
	}
	// Copy before imposing redirect and endpoint restrictions on test transports.
	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrDenied }
	copyClient.Transport = s3OnlyTransport{host: host, inner: httpClient.Transport}
	credentials := aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "browser-private-bootstrap"}
	client := s3.New(s3.Options{
		Region: c.Region, BaseEndpoint: aws.String("https://" + host), UsePathStyle: true,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			if c.Expires != 0 && time.Now().Unix() >= c.Expires {
				return aws.Credentials{}, ErrDenied
			}
			return credentials, nil
		}),
		HTTPClient: &copyClient, RetryMaxAttempts: 1,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &s3BlobBackend{client: client, bucket: c.Bucket, prefix: prefix}, nil
}

type s3OnlyTransport struct {
	host  string
	inner http.RoundTripper
}

func (t s3OnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil || r.URL.Fragment != "" || (r.Host != "" && r.Host != t.host) || t.inner == nil {
		return nil, ErrDenied
	}
	return t.inner.RoundTrip(r)
}

func (b *s3BlobBackend) Get(ctx context.Context, object string) ([]byte, string, error) {
	if !sealedObject.MatchString(object) {
		return nil, "", ErrInvalid
	}
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(b.bucket), Key: aws.String(b.prefix + object)})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && api.ErrorCode() == "NoSuchKey" {
			return nil, "", os.ErrNotExist
		}
		return nil, "", ErrUnavailable
	}
	defer out.Body.Close()
	version := aws.ToString(out.ETag)
	if !s3Version.MatchString(version) || out.ContentLength == nil || *out.ContentLength < 0 || *out.ContentLength > 33<<20 {
		return nil, "", ErrDenied
	}
	data, err := io.ReadAll(io.LimitReader(out.Body, (33<<20)+1))
	if err != nil || int64(len(data)) != *out.ContentLength || len(data) > 33<<20 {
		return nil, "", ErrDenied
	}
	return data, version, nil
}

func (b *s3BlobBackend) Put(ctx context.Context, object string, data []byte, version string) (string, error) {
	if !sealedObject.MatchString(object) || len(data) > 33<<20 || version != "" && !s3Version.MatchString(version) {
		return "", ErrInvalid
	}
	in := &s3.PutObjectInput{Bucket: aws.String(b.bucket), Key: aws.String(b.prefix + object), Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data))), ContentType: aws.String("application/octet-stream")}
	if version == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(version)
	}
	out, err := b.client.PutObject(ctx, in)
	if err != nil {
		return "", ErrUncertain
	}
	actual := aws.ToString(out.ETag)
	if !s3Version.MatchString(actual) {
		return "", ErrUncertain
	}
	return actual, nil
}
