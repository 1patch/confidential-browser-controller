package browser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// StorageLeaseIssuer is trusted controller code. An agent cannot select the
// role, bucket, prefix, endpoint or authority used to issue a credential.
type StorageLeaseIssuer interface {
	Issue(context.Context, string, string) (S3StoreConfig, error)
}

type StorageIssuerAuthority struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
	Expires         int64  `json:"expires,omitempty"`
}

type StorageIssuerRole struct {
	ARN        string `json:"arn"`
	ExternalID string `json:"externalId,omitempty"`
	Bucket     string `json:"bucket"`
	Region     string `json:"region"`
}

type StorageIssuerConfig struct {
	Authority StorageIssuerAuthority       `json:"authority"`
	Roles     map[string]StorageIssuerRole `json:"roles"`
}

type AWSStorageIssuer struct {
	client *sts.Client
	roles  map[string]StorageIssuerRole
}

var storageRoleARN = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
var storageExternalID = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]{2,256}$`)

func NewAWSStorageIssuer(c StorageIssuerConfig) (*AWSStorageIssuer, error) {
	return newAWSStorageIssuer(c, nil)
}

func newAWSStorageIssuer(c StorageIssuerConfig, testHTTP *http.Client) (*AWSStorageIssuer, error) {
	if len(c.Roles) < 1 || len(c.Roles) > 101 {
		return nil, ErrInvalid
	}
	a := c.Authority
	// Reuse the private credential/region bounds without constructing a default
	// AWS chain. This client never reads environment, profile or metadata keys.
	if _, err := newS3BlobBackend(S3StoreConfig{Bucket: "issuer-validation", Region: a.Region, AccessKeyID: a.AccessKeyID, SecretAccessKey: a.SecretAccessKey, SessionToken: a.SessionToken, Expires: a.Expires}, "system", "validation", nil); err != nil {
		return nil, ErrInvalid
	}
	roles, buckets, arns := map[string]StorageIssuerRole{}, map[string]bool{}, map[string]bool{}
	for owner, role := range c.Roles {
		if !identifier.MatchString(owner) || !storageRoleARN.MatchString(role.ARN) || strings.HasSuffix(role.ARN, "/") || (role.ExternalID != "" && !storageExternalID.MatchString(role.ExternalID)) || !s3Bucket.MatchString(role.Bucket) || strings.HasSuffix(role.Bucket, "--x-s3") || !s3Region.MatchString(role.Region) || strings.HasPrefix(role.Region, "cn-") || buckets[role.Bucket] || arns[role.ARN] {
			return nil, ErrDenied
		}
		roles[owner], buckets[role.Bucket], arns[role.ARN] = role, true, true
	}
	host := "sts." + a.Region + ".amazonaws.com"
	transport := http.RoundTripper(&http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second})
	if testHTTP != nil {
		transport = testHTTP.Transport
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: storageIssuerTransport{host: host, inner: transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}
	credentials := aws.Credentials{AccessKeyID: a.AccessKeyID, SecretAccessKey: a.SecretAccessKey, SessionToken: a.SessionToken, Source: "browser-private-issuer"}
	sdk := sts.New(sts.Options{Region: a.Region, BaseEndpoint: aws.String("https://" + host), HTTPClient: client, RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			if a.Expires != 0 && time.Now().Unix() >= a.Expires {
				return aws.Credentials{}, ErrDenied
			}
			return credentials, nil
		}),
	})
	return &AWSStorageIssuer{client: sdk, roles: roles}, nil
}

type storageIssuerTransport struct {
	host  string
	inner http.RoundTripper
}

func (t storageIssuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.Path != "/" || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawQuery != "" || (r.Host != "" && r.Host != t.host) || t.inner == nil {
		return nil, ErrDenied
	}
	response, err := t.inner.RoundTrip(r)
	if err != nil {
		return nil, ErrUnavailable
	}
	if response == nil || response.Body == nil {
		return nil, ErrUnavailable
	}
	response.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(response.Body, 64<<10), response.Body}
	return response, nil
}

func (i *AWSStorageIssuer) Issue(parent context.Context, owner, audience string) (S3StoreConfig, error) {
	if i == nil || i.client == nil {
		return S3StoreConfig{}, ErrDenied
	}
	role, ok := i.roles[owner]
	prefix, err := S3OwnerPrefix(owner, audience)
	if !ok || err != nil || parent.Err() != nil {
		return S3StoreConfig{}, ErrDenied
	}
	// Listing the dedicated owner bucket permits S3 to distinguish missing
	// objects from forbidden ones. Object reads/writes remain prefix-restricted.
	policy, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": []string{"s3:GetObject", "s3:PutObject"}, "Resource": "arn:aws:s3:::" + role.Bucket + "/" + prefix + "*"},
		map[string]any{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::" + role.Bucket},
	}})
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return S3StoreConfig{}, ErrUnavailable
	}
	session := "browser-" + hex.EncodeToString(random[:])
	input := &sts.AssumeRoleInput{RoleArn: aws.String(role.ARN), RoleSessionName: aws.String(session), DurationSeconds: aws.Int32(3600), Policy: aws.String(string(policy))}
	if role.ExternalID != "" {
		input.ExternalId = aws.String(role.ExternalID)
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	result, err := i.client.AssumeRole(ctx, input)
	// Do not expose AWS response/error text: it can contain authority details.
	if err != nil || result == nil || result.Credentials == nil || result.AssumedRoleUser == nil || result.Credentials.Expiration == nil || ctx.Err() != nil {
		return S3StoreConfig{}, ErrUnavailable
	}
	account := strings.Split(role.ARN, ":")[4]
	name := role.ARN[strings.LastIndex(role.ARN, "/")+1:]
	if aws.ToString(result.AssumedRoleUser.Arn) != "arn:aws:sts::"+account+":assumed-role/"+name+"/"+session {
		return S3StoreConfig{}, ErrDenied
	}
	c := result.Credentials
	storage := S3StoreConfig{Bucket: role.Bucket, Region: role.Region, AccessKeyID: aws.ToString(c.AccessKeyId), SecretAccessKey: aws.ToString(c.SecretAccessKey), SessionToken: aws.ToString(c.SessionToken), Expires: c.Expiration.Unix()}
	if storage.SessionToken == "" || storage.Expires <= time.Now().Add(40*time.Minute).Unix() || storage.Expires > started.Add(62*time.Minute).Unix() {
		return S3StoreConfig{}, ErrDenied
	}
	if _, err := newS3BlobBackend(storage, owner, audience, nil); err != nil {
		return S3StoreConfig{}, ErrDenied
	}
	return storage, nil
}
