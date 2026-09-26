package awsproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
	targets := []Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "r"}}, Regions: []string{"eu-*"}},
		{Profile: "prod", RoleARN: "arn:aws:iam::123456789012:role/prod", Services: []Service{{Name: "dynamodb", Mode: "rw"}}},
	}
	p := New(targets, "localhost")
	dir := t.TempDir()
	if err := p.syncOnce(12345, dir); err != nil {
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
	if err := p.syncOnce(12345, dir); err != nil || p.keys["dev"] != key {
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
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "ec2", Mode: "r"}}, Regions: []string{"eu-*"}},
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
	p := New([]Target{{Profile: "default", RoleARN: "arn:aws:iam::123456789012:role/default", Services: []Service{{Name: "sts", Mode: "r"}}}}, "localhost")
	if err := p.syncOnce(12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "default", p.targets)
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
	p := New([]Target{{Profile: "default", RoleARN: "arn:aws:iam::123456789012:role/default", Services: []Service{{Name: "sts", Mode: "r"}}}}, "localhost")
	if err := p.syncOnce(12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "default", p.targets)
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
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "sts", Mode: "r"}}}}, "localhost")
	if err := p.syncOnce(12345, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "dev", p.targets)
	if err != nil || creds.AccessKeyID != "ASSUMED" {
		t.Fatalf("regionless profile AssumeRole = %q, %v", creds.AccessKeyID, err)
	}
}

func TestSourceWatchKeepsLastGoodConfigOnInvalidRewrite(t *testing.T) {
	p, dir := awsTestProxy(t)
	p.SetTargets([]Target{{Profile: "*", RoleARN: "arn:aws:iam::123456789012:role/test", Services: []Service{{Name: "sts", Mode: "r"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- p.SyncConfig(ctx, 12345, dir, ready) }()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	p.mu.RLock()
	previousKey := p.keys["dev"]
	p.mu.RUnlock()
	path := os.Getenv("AWS_CONFIG_FILE")
	if err := os.WriteFile(path, []byte("[profile unfinished"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("watcher exited on invalid source config: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	p.mu.RLock()
	key := p.keys["dev"]
	p.mu.RUnlock()
	if key != previousKey {
		t.Fatal("invalid source config changed existing key")
	}
	if err := os.WriteFile(path, []byte("[profile dev]\n[profile prod]\n[profile new]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		p.mu.RLock()
		_, ok := p.keys["new"]
		p.mu.RUnlock()
		if ok {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("watcher exited before recovery: %v", err)
		case <-deadline:
			t.Fatal("watcher did not recover after source config was fixed")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestConcurrentConfigSyncKeepsFileAndIssuedKeyConsistent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	if err := os.WriteFile(filepath.Join(home, "config"), []byte("[profile dev]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "sts", Mode: "r"}}}}, "localhost")
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
				if err := p.syncOnce(12345, dir); err != nil {
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

func TestReloadDoesNotRecacheOldSourceCredentials(t *testing.T) {
	p, dir := awsTestProxy(t)
	requests := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer server.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int32
	p.loadSource = func(context.Context, string) (aws.Config, error) {
		key := "NEW"
		if loads.Add(1) == 1 {
			key = "OLD"
			close(entered)
			<-release
		}
		return aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: key, SecretAccessKey: "secret"}, nil
		})}, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.upstreamCredentials(context.Background(), "dev", p.targets)
		done <- err
	}()
	<-entered
	if err := p.Refresh(12345, dir); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := p.upstreamCredentials(context.Background(), "dev", p.targets); err != nil {
		t.Fatal(err)
	}
	if got := loads.Load(); got != 2 {
		t.Fatalf("source loads = %d, want 2 after reload", got)
	}
	if first, second := <-requests, <-requests; !strings.Contains(first, "Credential=OLD/") || !strings.Contains(second, "Credential=NEW/") {
		t.Errorf("STS used stale source after reload: %s, %s", first, second)
	}
}

func TestUpstreamCredentialsWithoutRole(t *testing.T) {
	p, _ := awsTestProxy(t)
	// With no roleArn the proxy must use the source profile's own
	// credentials directly, without calling sts:AssumeRole.
	p.SetTargets([]Target{{Profile: "dev", Services: []Service{{Name: "dynamodb", Mode: "r"}}}})
	if err := os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "dev", p.targets)
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "SOURCE" {
		t.Errorf("direct credentials = %q, want SOURCE", creds.AccessKeyID)
	}
}

func TestAssumeRoleWithoutSessionPolicy(t *testing.T) {
	p, _ := awsTestProxy(t)
	var requested url.Values
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		requested = r.Form
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	if err := os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := p.upstreamCredentials(context.Background(), "dev", p.targets)
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
	if _, err := p.upstreamCredentials(context.Background(), "dev", p.targets); err != nil {
		t.Fatal(err)
	}
}

func TestQueryProtocolReadAndWrite(t *testing.T) {
	target := Target{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "ec2", Mode: "r"}}}
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
	target := Target{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "kinesis", Mode: "r"}}}
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
	if err := p.syncOnce(listener.Addr().(*net.TCPAddr).Port, dir); err != nil {
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
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// The transport refuses what the stop cancelled: the wait ends
		// when the cancellation reaches the request, before anything
		// goes upstream. A request the stop did not cancel hangs here
		// — it is never delivered, whatever it carries.
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
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
	// No session: the credentials load runs per request. It waits for its
	// context — cut by the stop, never completed by a source.
	p.loadSource = func(ctx context.Context, profile string) (aws.Config, error) {
		select {
		case <-ctx.Done():
			return aws.Config{}, ctx.Err()
		}
	}
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
