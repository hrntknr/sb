package awsproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"gopkg.in/ini.v1"
)

func awsTestProxy(t *testing.T) (*Proxy, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "source-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "source-credentials"))
	if err := os.WriteFile(filepath.Join(home, "source-config"), []byte("[profile dev]\nregion = eu-west-1\n[profile prod]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The startup resolves each issued profile's upstream: the source
	// credentials the role's STS call signs with.
	if err := os.WriteFile(filepath.Join(home, "source-credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n[prod]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	testSTS(t)
	targets := []Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}},
		{Profile: "prod", RoleARN: "arn:aws:iam::123456789012:role/prod", Services: []Service{{Name: "dynamodb", Mode: "rw"}}},
	}
	p := New(targets, "localhost")
	dir := t.TempDir()
	if err := p.syncOnce(context.Background(), 12345, dir); err != nil {
		t.Fatal(err)
	}
	return p, dir
}

func signedRequest(t *testing.T, key issuedKey, region, target string, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://localhost:12345/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	r.Header.Set("X-Amz-Target", "DynamoDB_20120810."+target)
	hash := sha256.Sum256([]byte(body))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: key.ID, SecretAccessKey: key.Secret}, r, hex.EncodeToString(hash[:]), "dynamodb", region, time.Now()); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGeneratedProfiles(t *testing.T) {
	p, dir := awsTestProxy(t)
	config, err := ini.Load(filepath.Join(dir, ".aws", "config"))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := ini.Load(filepath.Join(dir, ".aws", "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dev", "prod"} {
		if config.Section("profile "+name).Key("endpoint_url").String() != "https://localhost:12345" {
			t.Fatalf("missing proxy endpoint for %s", name)
		}
		if credentials.Section(name).Key("aws_access_key_id").String() != p.keys[name].ID {
			t.Fatalf("missing downstream key for %s", name)
		}
	}
	if region := config.Section("profile dev").Key("region").String(); region != "eu-west-1" {
		t.Errorf("dev region = %q", region)
	}
	if credentials.HasSection("default") || credentials.HasSection("DEFAULT") && credentials.Section("DEFAULT").HasKey("aws_access_key_id") {
		t.Fatal("unallowed default credentials were issued")
	}
	if _, err := os.Stat(filepath.Join(dir, ".aws", "ca.pem")); err != nil {
		t.Fatal(err)
	}
	key := p.keys["dev"]
	if err := p.syncOnce(context.Background(), 12345, dir); err != nil || p.keys["dev"] != key {
		t.Fatalf("key changed across sync: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSignedRequestPolicyAndResigning(t *testing.T) {
	p, _ := awsTestProxy(t)
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	p.sessions["prod"] = session{role: "arn:aws:iam::123456789012:role/prod", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	forwarded := 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded++
		if !strings.HasPrefix(r.URL.Host, "dynamodb.") || !strings.Contains(r.Header.Get("Authorization"), "Credential=UPSTREAM/") {
			t.Errorf("upstream request not re-signed: %s %s", r.URL.Host, r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
	})
	for _, tt := range []struct {
		name                       string
		profile, region, operation string
		tamper                     func(*http.Request)
		want                       int
	}{
		{"allowed read", "dev", "eu-west-1", "GetItem", nil, 200},
		{"write forbidden", "dev", "eu-west-1", "PutItem", nil, 403},
		{"unknown operation forbidden", "dev", "eu-west-1", "TransactWriteItems", nil, 403},
		{"rw permits unlisted operation", "prod", "us-east-1", "TransactWriteItems", nil, 200},
		{"region forbidden", "dev", "us-east-1", "GetItem", nil, 403},
		{"wrong profile key", "prod", "eu-west-1", "GetItem", func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), p.keys["prod"].ID, p.keys["dev"].ID, 1))
		}, 401},
		{"tampered action", "dev", "eu-west-1", "GetItem", func(r *http.Request) {
			r.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
		}, 401},
		{"tampered body", "dev", "eu-west-1", "GetItem", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("{}"))
		}, 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := signedRequest(t, p.keys[tt.profile], tt.region, tt.operation, `{"TableName":"test","Key":{"id":{"S":"1"}}}`)
			if tt.tamper != nil {
				tt.tamper(r)
			}
			w := httptest.NewRecorder()
			p.serveHTTP(w, r)
			if w.Code != tt.want {
				t.Errorf("status = %d want %d: %s", w.Code, tt.want, w.Body.String())
			}
		})
	}
	if forwarded != 2 {
		t.Errorf("forwarded = %d want 2", forwarded)
	}
}

// signedRequestForService signs a request for any service with a form-encoded
// body; the X-Amz-Target header is set when target is non-empty, and is signed
// like a real client's would be.
func signedRequestForService(t *testing.T, key issuedKey, service, region, target string, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://localhost:12345/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if target != "" {
		r.Header.Set("X-Amz-Target", target)
	}
	hash := sha256.Sum256([]byte(body))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: key.ID, SecretAccessKey: key.Secret}, r, hex.EncodeToString(hash[:]), service, region, time.Now()); err != nil {
		t.Fatal(err)
	}
	return r
}

// Query and EC2 POST APIs carry the operation in a form-encoded Action parameter,
// so the authorized operation must come from the body the upstream executes.
// A read operation in a signed X-Amz-Target header must not authorize a write
// operation in the body.
func TestQueryAndEC2ProtocolsAuthorizeFormAction(t *testing.T) {
	p, _ := awsTestProxy(t)
	p.targets = []Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "ec2", Mode: "ro"}}, Regions: []string{"eu-*"}},
		{Profile: "prod", RoleARN: "arn:aws:iam::123456789012:role/prod", Services: []Service{{Name: "ec2", Mode: "rw"}}},
	}
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	p.sessions["prod"] = session{role: "arn:aws:iam::123456789012:role/prod", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	forwarded := 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded++
		if r.URL.Host != "ec2.eu-west-1.amazonaws.com" {
			t.Errorf("unexpected upstream host: %s", r.URL.Host)
		}
		if r.Header.Get("X-Amz-Target") != "" {
			t.Error("X-Amz-Target must not be forwarded for a query protocol")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
	})
	for _, tt := range []struct {
		name   string
		target string
		body   string
		want   int
	}{
		{"read from form action", "", "Action=DescribeInstances&Version=2016-11-15", 200},
		{"write from form action forbidden", "", "Action=TerminateInstances&Version=2016-11-15", 403},
		{"x-amz-target cannot swap the authorized operation", "Anything.DescribeInstances", "Action=TerminateInstances&Version=2016-11-15", 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := signedRequestForService(t, p.keys["dev"], "ec2", "eu-west-1", tt.target, tt.body)
			w := httptest.NewRecorder()
			p.serveHTTP(w, r)
			if w.Code != tt.want {
				t.Errorf("status = %d want %d: %s", w.Code, tt.want, w.Body.String())
			}
		})
	}
	if forwarded != 1 {
		t.Errorf("forwarded = %d want 1", forwarded)
	}
}

func TestClassifyValidatesProtocolShape(t *testing.T) {
	for _, tt := range []struct {
		name, service, contentType, target, body, want string
		endpoint                                       endpoint
	}{
		{"json", "sqs", "application/x-amz-json-1.0", "AmazonSQS.ListQueues", `{}`, "sqs:ListQueues", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.0", TargetPrefix: "AmazonSQS"}},
		{"json rejects form body", "sqs", "application/x-amz-json-1.0", "AmazonSQS.ListQueues", `Action=CreateQueue`, "", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.0", TargetPrefix: "AmazonSQS"}},
		{"json rejects form media type", "sqs", "application/x-www-form-urlencoded", "AmazonSQS.ListQueues", `{}`, "", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.0", TargetPrefix: "AmazonSQS"}},
		{"json rejects null body", "sqs", "application/x-amz-json-1.0", "AmazonSQS.ListQueues", `null`, "", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.0", TargetPrefix: "AmazonSQS"}},
		{"json rejects array body", "sqs", "application/x-amz-json-1.0", "AmazonSQS.ListQueues", `[]`, "", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.0", TargetPrefix: "AmazonSQS"}},
		{"json rejects wrong prefix", "sqs", "application/x-amz-json-1.0", "Other.ListQueues", `{}`, "", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.0", TargetPrefix: "AmazonSQS"}},
		{"dotted target prefix", "cloudtrail", "application/x-amz-json-1.1; charset=utf-8", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetTrail", `{}`, "cloudtrail:GetTrail", endpoint{Protocol: "json", ContentType: "application/x-amz-json-1.1", TargetPrefix: "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"}},
		{"query", "iam", "application/x-www-form-urlencoded; charset=utf-8", "", `Action=ListUsers&Version=2010-05-08`, "iam:ListUsers", endpoint{Protocol: "query", ContentType: "application/x-www-form-urlencoded"}},
		{"query rejects JSON media type", "iam", "application/x-amz-json-1.0", "", `Action=ListUsers`, "", endpoint{Protocol: "query", ContentType: "application/x-www-form-urlencoded"}},
		{"query rejects target", "iam", "application/x-www-form-urlencoded", "IAM.ListUsers", `Action=DeleteUser`, "", endpoint{Protocol: "query", ContentType: "application/x-www-form-urlencoded"}},
		{"query rejects duplicate action", "iam", "application/x-www-form-urlencoded", "", `Action=ListUsers&Action=DeleteUser`, "", endpoint{Protocol: "query", ContentType: "application/x-www-form-urlencoded"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.service, tt.endpoint, tt.contentType, tt.target, []byte(tt.body)); got != tt.want {
				t.Fatalf("classify() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifyUnsignedContentLength(t *testing.T) {
	p, _ := awsTestProxy(t)
	r := httptest.NewRequest(http.MethodPost, "https://localhost:12345/", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	r.Header.Set("X-Amz-Target", "DynamoDB_20120810.GetItem")
	actualLength := r.ContentLength
	r.ContentLength = 0 // Botocore signs before its HTTP transport adds Content-Length.
	hash := sha256.Sum256([]byte(`{}`))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, r, hex.EncodeToString(hash[:]), "dynamodb", "eu-west-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	r.ContentLength = actualLength
	if strings.Contains(r.Header.Get("Authorization"), "content-length") {
		t.Fatal("test request unexpectedly signed content-length")
	}
	match := credentialPattern.FindStringSubmatch(r.Header.Get("Authorization"))
	if !verify(r, p.keys["dev"], match, hex.EncodeToString(hash[:])) {
		t.Fatal("valid signature without a signed Content-Length was rejected")
	}
}

func testSTS(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	return server
}

func TestAssumeRoleFromDefaultEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "missing-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "missing-credentials"))
	t.Setenv("AWS_ACCESS_KEY_ID", "SOURCE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "source-secret")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_REGION", "us-east-1")
	testSTS(t)
	p := New([]Target{{Profile: "default", RoleARN: "arn:aws:iam::123456789012:role/default", Services: []Service{{Name: "sts", Mode: "ro"}}}}, "localhost")
	if err := p.syncOnce(context.Background(), 12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "default")
	if err != nil || creds.AccessKeyID != "ASSUMED" {
		t.Fatalf("default environment AssumeRole = %q, %v", creds.AccessKeyID, err)
	}
}

func TestAssumeRoleFromDefaultContainerCredentials(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	if err := os.WriteFile(configPath, []byte("[profile other]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "missing-credentials"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_REGION", "")
	containerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"AccessKeyId":"CONTAINER","SecretAccessKey":"secret","Token":"token","Expiration":"2099-01-01T00:00:00Z"}`)
	}))
	defer containerServer.Close()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", containerServer.URL)
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); !strings.Contains(auth, "Credential=CONTAINER/") || !strings.Contains(auth, "/us-east-1/sts/aws4_request") {
			t.Errorf("wrong source credentials: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{{Profile: "default", RoleARN: "arn:aws:iam::123456789012:role/default", Services: []Service{{Name: "sts", Mode: "ro"}}}}, "localhost")
	if err := p.syncOnce(context.Background(), 12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "default")
	if err != nil || creds.AccessKeyID != "ASSUMED" {
		t.Fatalf("default container credentials AssumeRole = %q, %v", creds.AccessKeyID, err)
	}
}

func TestAssumeRoleWithoutSourceRegion(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	credentialsPath := filepath.Join(dir, "credentials")
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	if err := os.WriteFile(credentialsPath, []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	testSTS(t)
	source, err := loadSourceConfig(context.Background(), "dev")
	if err != nil || source.Region != "us-east-1" {
		t.Fatalf("upstream STS region = %q, %v; want us-east-1", source.Region, err)
	}
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "sts", Mode: "ro"}}}}, "localhost")
	if err := p.syncOnce(context.Background(), 12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "dev")
	if err != nil || creds.AccessKeyID != "ASSUMED" {
		t.Fatalf("regionless profile AssumeRole = %q, %v", creds.AccessKeyID, err)
	}
}

// TestSyncConfigIssuesOncePerSession covers the fixed session: the source
// changes while it runs, and nothing follows it — no key changes, nothing
// reissues — until the next session, whose fresh issuance reads the
// changed source. Both sessions run the same wildcard policy, so the
// added profile's absence from the first session is the session, not a
// narrower policy.
func TestSyncConfigIssuesOncePerSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n[profile prod]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n[prod]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The wildcard resolves every existing profile, the default chain
	// included: the environment provides its credentials, and the STS
	// calls sign against the local STS.
	t.Setenv("AWS_ACCESS_KEY_ID", "SOURCE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "source-secret")
	testSTS(t)
	targets := []Target{{Profile: "*", RoleARN: "arn:aws:iam::123456789012:role/test", Services: []Service{{Name: "sts", Mode: "ro"}}}}
	p := New(targets, "localhost")
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- p.SyncConfig(ctx, 12345, dir, ready) }()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	p.mu.RLock()
	previous := p.keys["dev"]
	p.mu.RUnlock()

	// The source changes while the session runs: a new profile appears
	// in it — the fixed session does not follow, so the issued keys stay
	// and the added profile gets no key.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\n[profile prod]\n[profile new]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n[prod]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n[new]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	followed := func() bool {
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.keys["dev"] != previous || p.keys["new"].ID != ""
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		if followed() {
			t.Fatal("the fixed session followed a source change")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The next session: a fresh proxy and its initial issuance read the
	// changed source, so the added profile gets its key there.
	p2 := New(targets, "localhost")
	if err := p2.syncOnce(context.Background(), 12345, dir); err != nil {
		t.Fatal(err)
	}
	p2.mu.RLock()
	newKey := p2.keys["new"]
	p2.mu.RUnlock()
	if newKey.ID == "" {
		t.Fatal("the next session did not read the changed source")
	}
}

func TestConcurrentConfigSyncKeepsFileAndIssuedKeyConsistent(t *testing.T) {
	// A concurrent syncOnce can no longer happen while a request serves
	// (the session issues once and holds it), but the locking this guards
	// keeps what runs concurrently — a test's syncOnce against the issued
	// files, or a sync racing a loadSource in flight — consistent.
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	testSTS(t) // the concurrent issuances resolve the role upstream
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "sts", Mode: "ro"}}}}, "localhost")
	dir := t.TempDir()
	for round := 0; round < 8; round++ {
		p.mu.Lock()
		p.keys = map[string]issuedKey{}
		p.mu.Unlock()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := p.syncOnce(context.Background(), 12345, dir); err != nil {
					t.Errorf("syncOnce: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		file, err := ini.Load(filepath.Join(dir, ".aws", "credentials"))
		if err != nil {
			t.Fatal(err)
		}
		p.mu.RLock()
		key := p.keys["dev"].ID
		p.mu.RUnlock()
		if disk := file.Section("dev").Key("aws_access_key_id").String(); disk != key {
			t.Fatalf("round %d: file key %q != server key %q", round, disk, key)
		}
	}
}

// TestSyncConfigErrorsOnConflictingRoles covers the duplicate rules'
// startup error: rules matching one profile through a wildcard and an
// individual name disagree on the role, and the initial issuance's own
// result carries it — a start that waits for a ready that never comes
// would hang instead.
func TestSyncConfigErrorsOnConflictingRoles(t *testing.T) {
	p, _ := awsTestProxy(t)
	p.SetTargets([]Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev"},
		{Profile: "*", RoleARN: "arn:aws:iam::123456789012:role/other"},
	})
	err := p.SyncConfig(context.Background(), 12345, t.TempDir(), nil)
	if err == nil {
		t.Fatal("SyncConfig with conflicting rules; want a failure")
	}
	if !strings.Contains(err.Error(), "disagree on roleArn") {
		t.Fatalf("SyncConfig() = %v, want the roles' disagreement", err)
	}
}

// TestSyncConfigErrorsOnMissingProfile covers the missing target's startup
// error: a rule whose profile pattern matches no profile that exists in the
// source credentials would grant nothing, so the policy naming it fails.
func TestSyncConfigErrorsOnMissingProfile(t *testing.T) {
	p, _ := awsTestProxy(t)
	p.SetTargets([]Target{{Profile: "stage", Services: []Service{{Name: "dynamodb", Mode: "ro"}}}})
	err := p.SyncConfig(context.Background(), 12345, t.TempDir(), nil)
	if err == nil {
		t.Fatal("SyncConfig with a target that matches nothing; want a failure")
	}
	if !strings.Contains(err.Error(), "matches no profile") {
		t.Fatalf("SyncConfig() = %v, want the missing target", err)
	}
}

// TestSyncConfigErrorsOnCredentialFetchFailure covers the source
// credentials fetch failing at the startup: the chain's provider —
// whatever the source would resolve it to — cannot provide the
// profile's credentials, and the fetch's own failure is the start's
// result, not the first request's.
var errSourceCredentialsUnavailable = errors.New("source credentials unavailable")

func TestSyncConfigErrorsOnCredentialFetchFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The source cannot provide the profile's credentials: the injected
	// chain fails deterministically, whatever the environment would fall
	// to (the container or IMDS endpoints it would otherwise reach).
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}}}, "localhost")
	p.loadSource = func(context.Context, string) (aws.Config, error) {
		return aws.Config{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{}, errSourceCredentialsUnavailable
		})}, nil
	}
	dir := t.TempDir()
	// The start is bounded: a startup that waits for a ready that never
	// comes would hang instead.
	failure := make(chan error, 1)
	go func() {
		failure <- p.SyncConfig(context.Background(), 12345, dir, nil)
	}()
	var err error
	select {
	case err = <-failure:
	case <-time.After(10 * time.Second):
		t.Fatal("SyncConfig did not return: a start that waits for a ready that never comes held it")
	}
	if err == nil {
		t.Fatal("SyncConfig with a failing source; want a failure")
	}
	if !strings.Contains(err.Error(), "source credentials unavailable") {
		t.Fatalf("SyncConfig() = %v; want the credentials fetch's own failure", err)
	}
	// Nothing the failed start issued stays behind it.
	if _, statErr := os.Stat(filepath.Join(dir, ".aws")); !os.IsNotExist(statErr) {
		t.Fatalf(".aws still exists after the failed start: %v", statErr)
	}
}

// TestSyncConfigErrorsOnDeniedAssumeRole covers the role's AssumeRole
// failing at the startup: the STS denies the assumption, so the fetch's
// own failure is the start's result, not the first request's.
func TestSyncConfigErrorsOnDeniedAssumeRole(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The STS denies every AssumeRole it receives.
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>denied</Message></Error></ErrorResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}}}, "localhost")
	err := p.SyncConfig(context.Background(), 12345, t.TempDir(), nil)
	if err == nil {
		t.Fatal("SyncConfig with a denied AssumeRole; want a failure")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("SyncConfig() = %v; want the denied AssumeRole", err)
	}
}

// TestSessionResolutionDoesNotFollowTheSourceAfterReady covers the fixed
// session's resolution: the source credentials change after the ready,
// before any request — and what the request signs with stays the
// startup's own: the changed source never moves it.
func TestSessionResolutionDoesNotFollowTheSourceAfterReady(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	if err := p.syncOnce(context.Background(), 12345, dir); err != nil {
		t.Fatal(err)
	}
	// The source changes after the ready, before any request: the
	// downstream request still signs with the startup's own.
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = NEWACCESS\naws_secret_access_key = other-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	forwarded := make(chan string, 1)
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded <- r.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
	})
	r := signedRequest(t, p.keys["dev"], "eu-west-1", "GetItem", `{"TableName":"test","Key":{"id":{"S":"1"}}}`)
	w := httptest.NewRecorder()
	p.serveHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	select {
	case authorization := <-forwarded:
		// The final upstream signature carries the startup's own
		// credentials: the changed source never moved it.
		if !strings.Contains(authorization, "Credential=SOURCE/") || strings.Contains(authorization, "Credential=NEWACCESS/") {
			t.Fatalf("upstream signature = %q; want the startup's own source credentials", authorization)
		}
	default:
		t.Fatal("the request was not forwarded")
	}
}

// TestStopCutsTheSessionUpstream covers the stop cutting what its
// sources send: the startup's STS call — held open by the server —
// is refused or cut once the stop begins, so what it would send after
// the stop never goes out and the server sees the connection go.
func TestStopCutsTheSessionUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The STS server: it holds the session's call open and reports
	// the connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real service consumes the request body: the call it
		// carries is what the server reads. Consumed here, the
		// server watches the connection from then on — until then it
		// could not see the client go.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			cutOnce.Do(func() { close(cut) })
		case <-release:
			// The cleanup freed the handler: what the stop did
			// not cut, the cleanup did — not a success signal.
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer stsServer.Close()
	defer close(release)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: its STS call hangs in the
	// held request. The start is bounded: nothing returning is a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The session's STS call reached the server: the arrival is what
	// the stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the session's STS call did not reach the server")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The server saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight STS call")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut STS call; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

// TestStopCutsTheContainerCredentialsUpstream covers the stop cutting
// the container credentials fetch: the profile's own credentials — held
// open by the endpoint — are refused or cut once the stop begins, so
// what they would send after the stop never goes out and the
// endpoint sees the connection go.
func TestStopCutsTheContainerCredentialsUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No static source credentials: the profile's own fall to the
	// container endpoint — the chain fetches them there.
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The container credentials endpoint: it holds the fetch open
	// and reports the connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	credsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real endpoint consumes the request body: the fetch it
		// carries is what the endpoint reads. Consumed here, the
		// endpoint watches the connection from then on — until then
		// it could not see the client go.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			cutOnce.Do(func() { close(cut) })
		case <-release:
			// The cleanup freed the handler: what the stop did
			// not cut, the cleanup did — not a success signal.
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer credsServer.Close()
	defer close(release)
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", credsServer.URL)
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: the profile's own fetch hangs
	// in the held request. The start is bounded: nothing returning is
	// a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The profile's fetch reached the endpoint: the arrival is what
	// the stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the credentials fetch did not reach the endpoint")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The endpoint saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight credentials fetch")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut credentials fetch; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

// TestSuccessfulFetchesLeaveNoWatchBehind covers the watch's lifetime:
// the call's watch — the one that cuts its request when the stop begins
// — ends with the call, not with the session's stop. A fetch that
// succeeds without a stop must not leave one watching: each call that
// completed releases it.
func TestSuccessfulFetchesLeaveNoWatchBehind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No static source credentials: the profile's own fall to the
	// container endpoint — the chain fetches them there.
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The container credentials endpoint: it serves the credentials
	// and closes the connection after — the transport's connection
	// goroutines end when the connection does, not pooled for the
	// idle timeout.
	containerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, `{"AccessKeyId":"CONTAINER","SecretAccessKey":"secret","Token":"token","Expiration":"2099-01-01T00:00:00Z"}`)
	}))
	defer containerServer.Close()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", containerServer.URL)
	baseline := runtime.NumGoroutine()
	for i := 0; i < 4; i++ {
		// The load builds the chain — the container endpoint's
		// client — and the fetch goes over it and succeeds: the
		// credentials come back, no stop ever begins.
		cfg, err := loadSourceConfig(context.Background(), "dev")
		if err != nil {
			t.Fatal(err)
		}
		creds, err := cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if creds.AccessKeyID != "CONTAINER" {
			t.Fatalf("the fetch did not reach the endpoint: %v", creds.AccessKeyID)
		}
	}
	// Each fetch's watch ended with it: the count returns to the
	// baseline. A watch that stayed behind its call would hold the
	// count above it — one per fetch.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the watches did not leave: %d goroutines, want at most %d", runtime.NumGoroutine(), baseline+2)
}

// TestStopCutsTheSharedConfigAssumeRoleUpstream covers the stop cutting
// the chain's own STS call: the profile's role assumption — held open
// by the server — is refused or cut once the stop begins, so what it
// would send after the stop never goes out and the server sees the
// connection go.
func TestStopCutsTheSharedConfigAssumeRoleUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	// The profile assumes a role: its source is a second profile with
	// static credentials, and the chain's own STS client fetches the
	// role's credentials over the endpoint the environment names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile src]\nregion = eu-west-1\n\n[profile dev]\nregion = eu-west-1\nrole_arn = arn:aws:iam::123456789012:role/dev\nsource_profile = src\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[src]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n\n[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The STS endpoint: it holds the assumption open and reports the
	// connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real service consumes the request body: the call it
		// carries is what the endpoint reads. Consumed here, the
		// endpoint watches the connection from then on — until then
		// it could not see the client go.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			cutOnce.Do(func() { close(cut) })
		case <-release:
			// The cleanup freed the handler: what the stop did
			// not cut, the cleanup did — not a success signal.
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer stsServer.Close()
	defer close(release)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: the chain's own fetch hangs
	// in the held request. The start is bounded: nothing returning is
	// a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The chain's fetch reached the endpoint: the arrival is what the
	// stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the role assumption did not reach the endpoint")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The endpoint saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight role assumption")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut role assumption; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

// TestStopCutsTheWebIdentityUpstream covers the stop cutting the chain's
// own STS call for the web identity flow: the role's assumption from
// the token the file carries — held open by the server — is refused or
// cut once the stop begins, so what it would send after the stop never
// goes out and the server sees the connection go.
func TestStopCutsTheWebIdentityUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	// The profile assumes a role from a web identity token: the token
	// comes from a file, and the chain's own STS client fetches the
	// role's credentials over the endpoint the environment names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\nrole_arn = arn:aws:iam::123456789012:role/dev\nweb_identity_token_file = "+filepath.Join(home, "web-identity-token")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "web-identity-token"), []byte("web-identity-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The STS endpoint: it holds the assumption open and reports the
	// connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real service consumes the request body: the call it
		// carries is what the endpoint reads. Consumed here, the
		// endpoint watches the connection from then on — until then
		// it could not see the client go.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			cutOnce.Do(func() { close(cut) })
		case <-release:
			// The cleanup freed the handler: what the stop did
			// not cut, the cleanup did — not a success signal.
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer stsServer.Close()
	defer close(release)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: the chain's own fetch hangs
	// in the held request. The start is bounded: nothing returning is
	// a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The chain's fetch reached the endpoint: the arrival is what the
	// stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the role assumption did not reach the endpoint")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The endpoint saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight role assumption")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut role assumption; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

// TestStopCutsTheSSOTokenUpstream covers the stop cutting the chain's
// own OIDC call: the token the SSO session refreshes over — held open
// by the server — is refused or cut once the stop begins, so what it
// would send after the stop never goes out and the server sees the
// connection go.
func TestStopCutsTheSSOTokenUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	t.Setenv("HOME", home)
	// The profile's credentials come from an SSO session: the token
	// refresh goes over the chain's own OIDC client — the endpoint the
	// environment names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[sso-session sess]\nsso_start_url = https://example.awsapps.com/start\nsso_region = eu-west-1\n\n[profile dev]\nsso_session = sess\nsso_account_id = 123456789012\nsso_role_name = Role\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The cached token the refresh renews: expired, with what the
	// renewal sends — the refresh token and the client it goes as.
	cached, err := ssocreds.StandardCachedTokenFilepath("sess")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cached), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte(`{"accessToken":"expired","expiresAt":"2020-01-01T00:00:00Z","refreshToken":"refresh","clientId":"client","clientSecret":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The SSO OIDC endpoint: it holds the renewal open and reports the
	// connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real service consumes the request body: the call it
		// carries is what the endpoint reads. Consumed here, the
		// endpoint watches the connection from then on — until then
		// it could not see the client go.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			cutOnce.Do(func() { close(cut) })
		case <-release:
			// The cleanup freed the handler: what the stop did
			// not cut, the cleanup did — not a success signal.
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer oidcServer.Close()
	defer close(release)
	t.Setenv("AWS_ENDPOINT_URL_SSO_OIDC", oidcServer.URL)
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: the chain's own fetch hangs
	// in the held request. The start is bounded: nothing returning is
	// a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The chain's renewal reached the endpoint: the arrival is what
	// the stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the token renewal did not reach the endpoint")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The endpoint saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight token renewal")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut token renewal; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

// TestSyncConfigWithCABundle covers the load with a custom CA bundle:
// the bundle's certificate authority must resolve into the session's
// transport — the STS endpoint's certificate it authenticates — or
// the load that would set it fails.
func TestSyncConfigWithCABundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A CA that signs the STS endpoint's certificate, and the bundle
	// that carries it.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, serverKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	// The bundle the load reads: the CA's certificate.
	if err := os.WriteFile(filepath.Join(home, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The STS endpoint: its certificate is signed by the CA — the
	// session's STS call authenticates it with the bundle.
	stsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	stsServer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}}}
	stsServer.StartTLS()
	defer stsServer.Close()
	t.Setenv("AWS_CA_BUNDLE", filepath.Join(home, "ca.pem"))
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	// The startup resolves the session over TLS: the bundle's CA must
	// resolve into the transport, and the load must not fail setting it.
	if err := p.syncOnce(context.Background(), 12345, t.TempDir()); err != nil {
		t.Fatalf("SyncConfig with a CA bundle: %v", err)
	}
}

// TestSyncConfigUsesTheSharedConfigIMDSEndpoint covers the IMDS client
// the chain builds resolving its endpoint from the shared config: its
// requests go where the profile names — not the default address — and
// the startup that resolves the session with the credentials the chain
// retrieves there succeeds.
func TestSyncConfigUsesTheSharedConfigIMDSEndpoint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	// The IMDS endpoint: it serves the token, the credentials list,
	// and the credentials themselves, and reports the chain's arrival.
	reached := make(chan struct{}, 1)
	imdsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reached <- struct{}{}:
		default:
		}
		switch {
		case r.URL.Path == "/latest/api/token":
			// The token the chain's client carries from here: the
			// TTL names how long it holds.
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			_, _ = io.WriteString(w, "test-token")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			// The names of the profile's credentials: the first is
			// the one the chain resolves.
			_, _ = io.WriteString(w, "cred-name")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/cred-name":
			// The credentials the chain retrieves: what the session
			// signs with.
			_, _ = io.WriteString(w, `{"AccessKeyId":"SOURCE","SecretAccessKey":"source-secret","Token":"session","Expiration":"2099-01-01T00:00:00Z","Code":"Success"}`)
		default:
			t.Errorf("unexpected IMDS request: %s", r.URL.Path)
		}
	}))
	defer imdsServer.Close()
	// The STS endpoint: the session's own assumption succeeds there.
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	// The profile's own credentials fall to the IMDS the chain's
	// client fetches them from — at the endpoint the profile names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\nec2_metadata_service_endpoint = "+imdsServer.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	if err := p.syncOnce(context.Background(), 12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// The chain's requests reached the endpoint: the endpoint the
	// profile names is where they went.
	select {
	case <-reached:
	default:
		t.Fatal("the chain's requests did not reach the IMDS endpoint")
	}
}

// TestSyncConfigKeepsSharedConfigIMDSv1Disabled covers the shared
// config's v1 disablement holding: the chain's IMDS client does not
// fall back to v1 — the failed token fetch fails the chain, no
// request without the token follows it.
func TestSyncConfigKeepsSharedConfigIMDSv1Disabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	// The IMDS endpoint: it fails the token fetch — the v1 fallback
	// would send what follows without the token — and counts what
	// arrives.
	var requests atomic.Int32
	imdsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := requests.Add(1); n == 1 {
			// The token fetch fails: no token for what follows.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// The v1 fallback: the request goes without the token —
		// the disablement the profile set forbids it.
		_, _ = io.WriteString(w, "cred-name")
	}))
	defer imdsServer.Close()
	// The profile's own credentials fall to the IMDS the chain's
	// client fetches them from — with the v1 client disabled.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\nec2_metadata_service_endpoint = "+imdsServer.URL+"\nec2_metadata_v1_disabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	err := p.syncOnce(context.Background(), 12345, t.TempDir())
	if err == nil {
		t.Fatal("syncOnce with a v1-disabled token failure; want a failure")
	}
	// What arrived at the endpoint: the token fetch alone — no v1
	// request follows it.
	if n := requests.Load(); n != 1 {
		t.Fatalf("the endpoint saw %d requests; want the token fetch alone", n)
	}
}

// TestSyncConfigKeepsTheSharedConfigIMDSMode covers the shared config's
// endpoint mode holding: with the IPv6 mode set, the chain's IMDS client
// resolves at the endpoint the profile names — the mode does not break
// the resolution the config carries.
func TestSyncConfigKeepsTheSharedConfigIMDSMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The IMDS endpoint: it serves the token, the credentials list, and
	// the credentials themselves, and reports the chain's arrival.
	reached := make(chan struct{}, 1)
	imdsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reached <- struct{}{}:
		default:
		}
		switch {
		case r.URL.Path == "/latest/api/token":
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			_, _ = io.WriteString(w, "test-token")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			_, _ = io.WriteString(w, "cred-name")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/cred-name":
			_, _ = io.WriteString(w, `{"AccessKeyId":"SOURCE","SecretAccessKey":"source-secret","Token":"session","Expiration":"2099-01-01T00:00:00Z","Code":"Success"}`)
		default:
			t.Errorf("unexpected IMDS request: %s", r.URL.Path)
		}
	}))
	defer imdsServer.Close()
	// The STS endpoint: the session's own assumption succeeds there.
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	// The profile's own credentials fall to the IMDS the chain's client
	// fetches them from — with the IPv6 mode set at the endpoint the
	// profile names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\nec2_metadata_service_endpoint = "+imdsServer.URL+"\nec2_metadata_service_endpoint_mode = IPv6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	if err := p.syncOnce(context.Background(), 12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// The chain's requests reached the endpoint: the mode set did not
	// break the resolution.
	select {
	case <-reached:
	default:
		t.Fatal("the chain's requests did not reach the IMDS endpoint")
	}
}

// TestStopCutsTheIMDSTokenUpstream covers the stop cutting the IMDS
// token fetch: the token the chain's client requests — held open by
// the server — is refused or cut once the stop begins, so what it
// would send after the stop never goes out and the server sees the
// connection go.
func TestStopCutsTheIMDSTokenUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	// The IMDS endpoint: it holds the token fetch open and reports
	// the connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	imdsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real service consumes the request body: the call it
		// carries is what the endpoint reads. Consumed here, the
		// endpoint watches the connection from then on — until then
		// it could not see the client go.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			cutOnce.Do(func() { close(cut) })
		case <-release:
			// The cleanup freed the handler: what the stop did
			// not cut, the cleanup did — not a success signal.
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer imdsServer.Close()
	defer close(release)
	// The profile's own credentials fall to the IMDS the chain's
	// client fetches them from — at the endpoint the profile names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\nec2_metadata_service_endpoint = "+imdsServer.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: the chain's own fetch hangs
	// in the held request. The start is bounded: nothing returning is
	// a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The chain's fetch reached the endpoint: the arrival is what
	// the stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the token fetch did not reach the endpoint")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The endpoint saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight token fetch")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut token fetch; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

// TestStopCutsTheIMDSMetadataUpstream covers the stop cutting the IMDS
// metadata fetch: the credentials list the chain's client requests —
// held open by the server — is refused or cut once the stop begins,
// so what it would send after the stop never goes out and the server
// sees the connection go.
func TestStopCutsTheIMDSMetadataUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	// The IMDS endpoint: it serves the token and holds the metadata
	// fetch open, reporting the connection going when the stop cuts it.
	reached := make(chan struct{}, 1)
	cut := make(chan struct{})
	release := make(chan struct{})
	var cutOnce sync.Once
	imdsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/latest/api/token":
			// The token the chain's client carries from here: the
			// TTL names how long it holds.
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			_, _ = io.WriteString(w, "test-token")
		default:
			// The real service consumes the request body: the call it
			// carries is what the endpoint reads. Consumed here, the
			// endpoint watches the connection from then on — until
			// then it could not see the client go.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case reached <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
				cutOnce.Do(func() { close(cut) })
			case <-release:
				// The cleanup freed the handler: what the stop
				// did not cut, the cleanup did — not a success
				// signal.
			}
		}
	}))
	// The cleanup frees the handler whatever the stop cut: without
	// it the close would wait for it to go.
	defer imdsServer.Close()
	defer close(release)
	// The profile's own credentials fall to the IMDS the chain's
	// client fetches them from — at the endpoint the profile names.
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\nec2_metadata_service_endpoint = "+imdsServer.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}}}, "localhost")
	dir := t.TempDir()
	// The startup resolves the session: the chain's own fetch hangs
	// in the held request. The start is bounded: nothing returning is
	// a hang.
	started := make(chan error, 1)
	go func() { started <- p.SyncConfig(context.Background(), 12345, dir, nil) }()
	// The chain's fetch reached the endpoint: the arrival is what
	// the stop cuts from.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the metadata fetch did not reach the endpoint")
	}
	// The stop begins: what is in flight is cut.
	p.BeginStop()
	select {
	case <-cut:
		// The endpoint saw the connection go: the transport cut it.
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not cut the in-flight metadata fetch")
	}
	// The startup fails with its own result.
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("SyncConfig with a cut metadata fetch; want a failure")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the startup did not return")
	}
}

func TestUpstreamCredentialsWithoutRole(t *testing.T) {
	p, dir := awsTestProxy(t)
	// With no roleArn the proxy must use the source profile's own
	// credentials directly, without calling sts:AssumeRole.
	p.SetTargets([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "ro"}}}})
	if err := p.syncOnce(context.Background(), 12345, dir); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "SOURCE" {
		t.Errorf("direct credentials = %q, want SOURCE", creds.AccessKeyID)
	}
}

func TestAssumeRoleWithoutSessionPolicy(t *testing.T) {
	p, dir := awsTestProxy(t)
	var requested url.Values
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		// Only the dev profile's form is recorded: the prod resolution
		// uses the same server, and the assertions below are the dev
		// session's own.
		if r.Form.Get("RoleArn") == "arn:aws:iam::123456789012:role/dev" {
			requested = r.Form
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	// The startup resolution against this STS: what it sends is the
	// session's own.
	if err := p.syncOnce(context.Background(), 12345, dir); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	// The upstream credentials carry only the role; the session policy is
	// gone and the proxy filter enforces the per-request policy.
	if creds.AccessKeyID != "ASSUMED" || requested.Get("RoleArn") != "arn:aws:iam::123456789012:role/dev" {
		t.Errorf("unexpected assumed credentials or role: %q %q", creds.AccessKeyID, requested.Get("RoleArn"))
	}
	if got := requested.Get("Policy"); got != "" {
		t.Errorf("AssumeRole must not send a session policy, got %q", got)
	}
	// The provider caches the temporary role credentials for subsequent calls.
	if _, err := p.upstreamCredentials(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
}

// TestPerProfileRoleAndUpstreamCredentials covers the per-profile
// resolution: two profiles with different roles — each one's requests
// carry their own role's upstream, the access key the final upstream
// signature signs with — so a regression that swaps the profiles'
// sessions or credentials cannot pass unnoticed.
func TestPerProfileRoleAndUpstreamCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\nregion = eu-west-1\n[profile prod]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "credentials"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n[prod]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The STS response carries the role's own access key: the key the
	// final upstream signature uses identifies the role that assumed it.
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		var key string
		switch r.Form.Get("RoleArn") {
		case "arn:aws:iam::123456789012:role/a":
			key = "AASSUMED"
		case "arn:aws:iam::123456789012:role/b":
			key = "BASSUMED"
		default:
			t.Errorf("unexpected RoleArn %q", r.Form.Get("RoleArn"))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>`+key+`</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	p := New([]Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/a", Services: []Service{{Name: "dynamodb", Mode: "ro"}}, Regions: []string{"eu-*"}},
		{Profile: "prod", RoleARN: "arn:aws:iam::123456789012:role/b", Services: []Service{{Name: "dynamodb", Mode: "rw"}}, Regions: []string{"us-*"}},
	}, "localhost")
	dir := t.TempDir()
	if err := p.syncOnce(context.Background(), 12345, dir); err != nil {
		t.Fatal(err)
	}
	forwarded := make(chan string, 2)
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded <- r.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
	})
	// A valid signed request per profile: each one's upstream carries its
	// own role's assumed key, never the other's.
	for _, tt := range []struct {
		profile, region, wantCredential string
	}{
		{"dev", "eu-west-1", "Credential=AASSUMED/"},
		{"prod", "us-east-1", "Credential=BASSUMED/"},
	} {
		r := signedRequest(t, p.keys[tt.profile], tt.region, "GetItem", `{"TableName":"test","Key":{"id":{"S":"1"}}}`)
		w := httptest.NewRecorder()
		p.serveHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status = %d: %s", tt.profile, w.Code, w.Body.String())
		}
		select {
		case authorization := <-forwarded:
			if !strings.Contains(authorization, tt.wantCredential) {
				t.Fatalf("%s: upstream signature = %q; want it to carry %q", tt.profile, authorization, tt.wantCredential)
			}
		default:
			t.Fatal(tt.profile + ": the request was not forwarded")
		}
	}
}

func TestQueryProtocolReadAndWrite(t *testing.T) {
	target := Target{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "ec2", Mode: "ro"}}}
	p := New([]Target{target}, "localhost")
	p.keys["dev"] = issuedKey{ID: "SBTEST", Secret: "downstream-secret"}
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "ec2.us-east-1.amazonaws.com" {
			t.Errorf("unexpected upstream: %s", r.URL.Host)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	for _, tt := range []struct {
		operation string
		want      int
	}{{"DescribeInstances", 200}, {"TerminateInstances", 403}, {"UnknownOperation", 403}} {
		body := "Action=" + tt.operation + "&Version=2016-11-15"
		r := httptest.NewRequest(http.MethodPost, "https://localhost:12345/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hash := sha256.Sum256([]byte(body))
		if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, r, hex.EncodeToString(hash[:]), "ec2", "us-east-1", time.Now()); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		p.serveHTTP(w, r)
		if w.Code != tt.want {
			t.Errorf("%s: got %d want %d: %s", tt.operation, w.Code, tt.want, w.Body.String())
		}
	}
}

func TestJSONProtocolBeyondPinnedServices(t *testing.T) {
	target := Target{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "kinesis", Mode: "ro"}}}
	p := New([]Target{target}, "localhost")
	p.keys["dev"] = issuedKey{ID: "SBTEST", Secret: "downstream-secret"}
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "kinesis.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Target") != "Kinesis_20131202.ListStreams" {
			t.Errorf("unexpected upstream %s %q", r.URL.Host, r.Header.Get("X-Amz-Target"))
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	for _, tt := range []struct {
		target string
		want   int
	}{{"Kinesis_20131202.ListStreams", 200}, {"Kinesis_20131202.CreateStream", 403}, {"Kinesis_20131202.UnknownOperation", 403}} {
		body := `{}`
		r := httptest.NewRequest(http.MethodPost, "https://localhost:12345/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-amz-json-1.1")
		r.Header.Set("X-Amz-Target", tt.target)
		hash := sha256.Sum256([]byte(body))
		if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, r, hex.EncodeToString(hash[:]), "kinesis", "us-east-1", time.Now()); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		p.serveHTTP(w, r)
		if w.Code != tt.want {
			t.Errorf("%s: got %d want %d: %s", tt.target, w.Code, tt.want, w.Body.String())
		}
	}
}

func TestEndpointForwardingUsesModelPrefixes(t *testing.T) {
	// The SigV4 credential carries the SDK signing name (ses, iam); the
	// upstream host uses the botocore endpoint prefix (ses→email) and skips the
	// region for global endpoints (iam→iam.amazonaws.com).
	target := Target{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "ses", Mode: "rw"}, {Name: "iam", Mode: "rw"}}}
	p := New([]Target{target}, "localhost")
	p.keys["dev"] = issuedKey{ID: "SBTEST", Secret: "downstream-secret"}
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "UPSTREAM", SecretAccessKey: "upstream-secret"}, nil
	})}
	for _, tt := range []struct {
		service, region, body, wantHost string
		want                            int
	}{
		{"ses", "us-east-1", "Action=ListTemplates&Version=2010-12-01", "email.us-east-1.amazonaws.com", 200},
		{"iam", "eu-west-1", "Action=GetAccountSummary&Version=2010-05-08", "iam.amazonaws.com", 200},
		{"route53", "us-east-1", "Action=ListHostedZones&Version=2013-04-01", "", 403},
	} {
		r := httptest.NewRequest(http.MethodPost, "https://localhost:12345/", strings.NewReader(tt.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hash := sha256.Sum256([]byte(tt.body))
		if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, r, hex.EncodeToString(hash[:]), tt.service, tt.region, time.Now()); err != nil {
			t.Fatal(err)
		}
		forwarded := ""
		p.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			forwarded = req.URL.Host
			if tt.service == "iam" && !strings.Contains(req.Header.Get("Authorization"), "/us-east-1/iam/aws4_request") {
				t.Errorf("IAM upstream signing scope = %q", req.Header.Get("Authorization"))
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})
		w := httptest.NewRecorder()
		p.serveHTTP(w, r)
		if w.Code != tt.want || forwarded != tt.wantHost {
			t.Errorf("%s/%s: status %d forwarded %q want %q: %s", tt.service, tt.region, w.Code, forwarded, tt.wantHost, w.Body.String())
		}
	}
}

func TestGeneratedCAAuthenticatesProxy(t *testing.T) {
	p, dir := awsTestProxy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := p.syncOnce(context.Background(), listener.Addr().(*net.TCPAddr).Port, dir); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Serve(listener) }()
	ca, err := os.ReadFile(filepath.Join(dir, ".aws", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid generated CA")
	}
	request := httptest.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/", strings.NewReader(`{}`))
	request.RequestURI = ""
	request.Header.Set("Content-Type", "application/x-amz-json-1.0")
	request.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
	hash := sha256.Sum256([]byte(`{}`))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, request, hex.EncodeToString(hash[:]), "dynamodb", "eu-west-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

// TestShutdownCutsLingeringRequestAtDeadline covers the deadline of the stop
// flow: a request the upstream never completes (logs -f, long polls) is cut
// at the deadline, not waited for.
func TestShutdownCutsLingeringRequestAtDeadline(t *testing.T) {
	p, _ := awsTestProxy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release := make(chan struct{})
	defer close(release)
	// The session exists, so the credentials load is skipped: the request
	// goes straight to the final upstream call, the one the stop cuts.
	p.mu.Lock()
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, nil
	})}
	p.mu.Unlock()
	aborted := make(chan struct{})
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		go func() {
			// The upstream request carries the stop context: BeginStop
			// cancels it here.
			<-r.Context().Done()
			close(aborted)
		}()
		<-release // the upstream never completes while this is held open
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
	})
	go func() { _ = p.Serve(listener) }()

	request := httptest.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/", strings.NewReader(`{}`))
	request.RequestURI = ""
	request.Header.Set("Content-Type", "application/x-amz-json-1.0")
	request.Header.Set("X-Amz-Target", "DynamoDB_20120810.GetItem")
	hash := sha256.Sum256([]byte(`{}`))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, request, hex.EncodeToString(hash[:]), "dynamodb", "eu-west-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	done := make(chan error, 1)
	go func() {
		_, err := client.Do(request)
		done <- err
	}()

	// Let the request reach the hanging upstream.
	time.Sleep(100 * time.Millisecond)
	// The stop start: the upstream request is cancelled here — before
	// anything waits on it.
	p.BeginStop()
	select {
	case <-aborted:
	case <-time.After(2 * time.Second):
		t.Fatal("the upstream request was not cancelled by the stop start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	p.Shutdown(ctx)
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("Shutdown waited %v; want it cut at the deadline", waited)
	}

	// The lingering request is cut: its connection is closed.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the lingering request completed; want it cut")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the lingering request was not cut at the deadline")
	}
}

// TestRequestsAfterTheStopNeverReachUpstream covers the stop state: a
// request issued after the stop began (the credentials load skipped, the
// final upstream call next) inherits the stop's cancellation — the upstream
// it would reach never learns about it.
func TestRequestsAfterTheStopNeverReachUpstream(t *testing.T) {
	p, _ := awsTestProxy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// The session exists, so the credentials load is skipped: the request
	// goes straight to the final upstream call.
	p.mu.Lock()
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, nil
	})}
	p.mu.Unlock()
	sentUpstream := int32(0)
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// The transport refuses what the stop cancelled: the refusal
		// reads the context's Done without waiting, like a real
		// transport, which delivers nothing once the context's Done
		// is closed. What it would send instead — a request the
		// stop did not cancel — goes to the upstream: count it, the
		// test fails on a nonzero count.
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		default:
			atomic.AddInt32(&sentUpstream, 1)
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
		}
	})
	go func() { _ = p.Serve(listener) }()

	// The stop begins before the request exists: whatever it issues from
	// here carries the stop.
	p.BeginStop()

	request := httestSignedAWSRequest(t, listener, p)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	done := make(chan struct{})
	go func() {
		response, err := client.Do(request)
		if err != nil {
			t.Errorf("Do() after the stop began: %v", err)
		} else {
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d; want %d (the request must fail before the upstream)", response.StatusCode, http.StatusBadGateway)
			}
		}
		close(done)
	}()
	select {
	case <-done:
		// The request completed without reaching the upstream: the
		// transport refused what the stop cancelled, and the request
		// never went past it.
		if sentUpstream != 0 {
			t.Fatalf("a request issued after the stop began was sent upstream %d times", sentUpstream)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a request issued after the stop began did not complete")
	}
}

// TestRequestsStoppedMidCredentialsNeverReachUpstream covers a request
// stuck in its credentials load when the stop begins: the load is cut there
// — the request never resolves the upstream call it was heading for, so
// the upstream never learns about it.
func TestRequestsStoppedMidCredentialsNeverReachUpstream(t *testing.T) {
	p, _ := awsTestProxy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// The session exists: its credentials hang on the context the
	// request would load them under — cut by the stop, never completed
	// by a source.
	p.mu.Lock()
	p.sessions["dev"] = session{role: "arn:aws:iam::123456789012:role/dev", credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		select {
		case <-ctx.Done():
			return aws.Credentials{}, ctx.Err()
		}
	})}
	p.mu.Unlock()
	hits := int32(0)
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&hits, 1)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString("ok"))}, nil
	})
	go func() { _ = p.Serve(listener) }()

	// The stop begins before the request exists: the load's context is
	// cancelled from its first use.
	p.BeginStop()

	request := httestSignedAWSRequest(t, listener, p)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	done := make(chan struct{})
	go func() {
		response, err := client.Do(request)
		if err == nil {
			defer response.Body.Close()
			if hits != 0 {
				t.Errorf("a request stopped mid-credentials reached the upstream %d times", hits)
			}
			if response.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d; want %d (the credentials load must fail before the upstream)", response.StatusCode, http.StatusBadGateway)
			}
		} else {
			t.Errorf("Do() stopped mid-credentials: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a request whose load was cut by the stop did not complete")
	}
}

// httestSignedAWSRequest builds a signed downstream request against the
// proxy's listener, the way TestShutdownCutsLingeringRequestAtDeadline
// does: the same request for each of the stop tests.
func httestSignedAWSRequest(t *testing.T, listener net.Listener, p *Proxy) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/", strings.NewReader(`{}`))
	request.RequestURI = ""
	request.Header.Set("Content-Type", "application/x-amz-json-1.0")
	request.Header.Set("X-Amz-Target", "DynamoDB_20120810.GetItem")
	hash := sha256.Sum256([]byte(`{}`))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: p.keys["dev"].ID, SecretAccessKey: p.keys["dev"].Secret}, request, hex.EncodeToString(hash[:]), "dynamodb", "eu-west-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	return request
}
