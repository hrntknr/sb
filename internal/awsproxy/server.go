package awsproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hrntknr/sb/internal/util"
)

type issuedKey struct{ ID, Secret string }
type session struct {
	role        string
	credentials aws.CredentialsProvider
}

type Proxy struct {
	host       string
	syncMu     sync.Mutex
	mu         sync.RWMutex
	targets    []Target
	keys       map[string]issuedKey
	sessions   map[string]session
	generation uint64
	loadSource func(context.Context, string) (aws.Config, error)
	certOnce   sync.Once
	cert       tls.Certificate
	certErr    error
	server     *http.Server
	client      *http.Client
}

func New(targets []Target, host string) *Proxy {
	return &Proxy{host: host, targets: targets, keys: map[string]issuedKey{}, sessions: map[string]session{}, loadSource: loadSourceConfig, client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (p *Proxy) certificate() (tls.Certificate, error) {
	p.certOnce.Do(func() { p.cert, p.certErr = util.IssueCertificate(p.host) })
	return p.cert, p.certErr
}

func (p *Proxy) SetTargets(targets []Target) {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	p.mu.Lock()
	p.targets = targets
	p.sessions = map[string]session{}
	p.generation++
	p.mu.Unlock()
}

func (p *Proxy) Serve(listener net.Listener) error {
	cert, err := p.certificate()
	if err != nil {
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(p.serveHTTP), TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	}}
	p.setServer(server)
	return server.ServeTLS(listener, "", "")
}

// Shutdown stops the server: it stops accepting new requests, waits for
// active ones to finish, and closes the rest at ctx's deadline (streams
// that never go idle are cut there).
func (p *Proxy) Shutdown(ctx context.Context) {
	server := p.getServer()
	if server == nil {
		return
	}
	if err := server.Shutdown(ctx); err != nil {
		server.Close()
	}
}

func (p *Proxy) setServer(server *http.Server) {
	p.mu.Lock()
	p.server = server
	p.mu.Unlock()
}

func (p *Proxy) getServer() *http.Server {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.server
}

var (
	credentialPattern = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/ ]+)/([0-9]{8})/([a-z0-9-]+)/([a-z0-9-]+)/aws4_request, SignedHeaders=([-a-z0-9;]+), Signature=([0-9a-f]{64})$`)
)

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	match := credentialPattern.FindStringSubmatch(r.Header.Get("Authorization"))
	if match == nil || r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" {
		http.Error(w, "unsupported AWS request", http.StatusBadRequest)
		return
	}
	service, region := match[4], match[3]
	endpoint, forwardable := serviceEndpoints[service]
	if !forwardable || !supportedProtocols[endpoint.Protocol] {
		http.Error(w, "unsupported AWS service", http.StatusForbidden)
		return
	}
	p.mu.RLock()
	profile, key := "", issuedKey{}
	for name, candidate := range p.keys {
		if candidate.ID == match[1] {
			profile, key = name, candidate
			break
		}
	}
	targets := p.targets
	p.mu.RUnlock()
	if profile == "" || r.Header.Get("X-Amz-Security-Token") != "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])
	if supplied := r.Header.Get("X-Amz-Content-Sha256"); supplied != "" && supplied != payloadHash {
		http.Error(w, "invalid payload hash", http.StatusUnauthorized)
		return
	}
	if !verify(r, key, match, payloadHash) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	action := classify(service, endpoint, r.Header.Get("Content-Type"), r.Header.Get("X-Amz-Target"), body)
	if !allows(targets, profile, region, action) {
		slog.Warn("rejected aws request", "profile", profile, "region", region, "action", action)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	credentials, err := p.upstreamCredentials(r.Context(), profile, targets)
	if err != nil {
		slog.Error("aws upstream credentials failed", "profile", profile, "error", err)
		http.Error(w, "upstream credentials unavailable", http.StatusBadGateway)
		return
	}
	host := strings.ReplaceAll(endpoint.Host, "{region}", region)
	upstreamURL := &url.URL{Scheme: "https", Host: host, Path: "/"}
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	upstream.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	if r.Header.Get("X-Amz-Target") != "" {
		upstream.Header.Set("X-Amz-Target", r.Header.Get("X-Amz-Target"))
	}
	signingRegion := endpoint.SigningRegion
	if signingRegion == "" {
		signingRegion = region
	}
	if err := v4.NewSigner().SignHTTP(r.Context(), credentials, upstream, payloadHash, service, signingRegion, time.Now()); err != nil {
		http.Error(w, "sign upstream request failed", http.StatusBadGateway)
		return
	}
	response, err := p.client.Do(upstream)
	if err != nil {
		slog.Error("aws upstream request failed", "profile", profile, "error", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

// classify determines the operation the upstream will execute. JSON POST
// APIs carry it in X-Amz-Target; Query and EC2 POST APIs in a form-encoded
// Action parameter. A request carrying the wrong header for its protocol,
// or none at all, has no classifiable operation and is rejected.
func classify(service string, endpoint endpoint, contentType, target string, body []byte) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != endpoint.ContentType {
		return ""
	}
	if endpoint.Protocol != "json" {
		if target != "" {
			return ""
		}
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values["Action"]) != 1 {
			return ""
		}
		return service + ":" + values.Get("Action")
	}
	prefix := endpoint.TargetPrefix + "."
	operation, ok := strings.CutPrefix(target, prefix)
	var payload map[string]json.RawMessage
	if !ok || operation == "" || json.Unmarshal(body, &payload) != nil || payload == nil {
		return ""
	}
	return service + ":" + operation
}

func verify(r *http.Request, key issuedKey, match []string, payloadHash string) bool {
	date, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || date.Format("20060102") != match[2] {
		return false
	}
	if age := time.Since(date); age < -5*time.Minute || age > 5*time.Minute {
		return false
	}
	signed := strings.Split(match[5], ";")
	if !slices.Contains(signed, "host") || !slices.Contains(signed, "x-amz-date") || r.Header.Get("X-Amz-Target") != "" && !slices.Contains(signed, "x-amz-target") {
		return false
	}
	cloned := r.Clone(r.Context())
	if !slices.Contains(signed, "content-length") {
		cloned.ContentLength = 0
	}
	cloned.Header = make(http.Header)
	for _, name := range signed {
		if name == "host" {
			continue
		}
		if name == "content-length" {
			if r.ContentLength < 0 || r.Header.Get("Content-Length") != "" && r.Header.Get("Content-Length") != strconv.FormatInt(r.ContentLength, 10) {
				return false
			}
			continue
		}
		values := r.Header.Values(name)
		if len(values) == 0 {
			return false
		}
		cloned.Header[http.CanonicalHeaderKey(name)] = values
	}
	cloned.Header.Del("Authorization")
	if err := v4.NewSigner().SignHTTP(r.Context(), aws.Credentials{AccessKeyID: key.ID, SecretAccessKey: key.Secret}, cloned, payloadHash, match[4], match[3], date); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cloned.Header.Get("Authorization")), []byte(r.Header.Get("Authorization"))) == 1
}

func (p *Proxy) upstreamCredentials(ctx context.Context, profile string, targets []Target) (aws.Credentials, error) {
	role, err := assumedRole(targets, profile)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws profile %s: %w", profile, err)
	}
	p.mu.RLock()
	current, ok := p.sessions[profile]
	generation := p.generation
	p.mu.RUnlock()
	if !ok || current.role != role {
		source, err := p.loadSource(ctx, profile)
		if err != nil {
			return aws.Credentials{}, err
		}
		var provider aws.CredentialsProvider = source.Credentials
		if role != "" {
			provider = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(source), role, func(options *stscreds.AssumeRoleOptions) {
				options.RoleSessionName = "sb"
			})
		}
		current = session{role: role, credentials: aws.NewCredentialsCache(provider)}
		p.mu.Lock()
		if p.generation == generation {
			p.sessions[profile] = current
		}
		p.mu.Unlock()
	}
	return current.credentials.Retrieve(ctx)
}
