package awsproxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/hrntknr/sb/internal/util"
	"gopkg.in/ini.v1"
)

var profileName = regexp.MustCompile(`^[a-zA-Z0-9_.@+\-]+$`)

func sourceFiles() []string {
	home, _ := os.UserHomeDir()
	config := os.Getenv("AWS_CONFIG_FILE")
	if config == "" {
		config = filepath.Join(home, ".aws", "config")
	}
	credentials := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credentials == "" {
		credentials = filepath.Join(home, ".aws", "credentials")
	}
	return []string{config, credentials}
}

func profiles() ([]string, map[string]string, error) {
	names := map[string]bool{}
	regions := map[string]string{}
	for i, path := range sourceFiles() {
		config, err := ini.Load(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read aws profiles %s: %w", path, err)
		}
		for _, section := range config.Sections() {
			name := section.Name()
			if i == 0 {
				name = strings.TrimPrefix(name, "profile ")
			}
			if name == "DEFAULT" {
				name = "default"
			}
			if profileName.MatchString(name) {
				names[name] = true
				if i == 0 && section.HasKey("region") {
					regions[name] = section.Key("region").String()
				}
			}
		}
	}
	// The default credential chain can use environment or instance credentials.
	names["default"] = true
	var result []string
	for name := range names {
		result = append(result, name)
	}
	slices.Sort(result)
	return result, regions, nil
}

// SyncConfig issues the session's AWS credentials under dir once: it
// expands the policy's profile patterns to the profiles that exist in
// the source credentials, checks the matching rules agree on the role,
// and issues the downstream-only credentials — all fixed for the
// session. It signals the issuance's own result through ready (nil: the
// issuance succeeded), and then holds the session open until the run
// ends or the stop begins: a source change lands next session.
func (p *Proxy) SyncConfig(ctx context.Context, port int, dir string, ready chan<- error) error {
	// result reports the issuance's own outcome through ready, so the
	// start waiting on it learns about a failed setup: without it the
	// caller would wait forever for an issuance that never began.
	result := func(err error) error {
		if ready != nil {
			ready <- err
		}
		return err
	}
	if err := p.syncOnce(port, dir); err != nil {
		return result(err)
	}
	if ready != nil {
		// The initial issuance's own result, not just its completion.
		ready <- nil
	}
	// The session is fixed: nothing follows the source, and nothing
	// reissues. Wait for the end — the run's (ctx) or the stop's,
	// whichever comes first.
	<-p.stopContext(ctx).Done()
	return nil
}

func (p *Proxy) syncOnce(port int, dir string) error {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	p.mu.RLock()
	old := p.keys
	targets := p.targets
	p.mu.RUnlock()
	var names []string
	var regions map[string]string
	if len(targets) > 0 {
		var err error
		names, regions, err = profiles()
		if err != nil {
			return err
		}
		// A rule that matches no existing profile would grant nothing:
		// the target it names does not exist, so the policy naming it is
		// a startup error.
		for _, target := range targets {
			if !slices.ContainsFunc(names, func(name string) bool { return util.Match(target.Profile, name) }) {
				return fmt.Errorf("aws: profile %q %w", target.Profile, errMissingProfiles)
			}
		}
	}
	keys := map[string]issuedKey{}
	var config, credentials strings.Builder
	for _, name := range names {
		if !hasProfile(targets, name) {
			continue
		}
		if _, err := assumedRole(targets, name); err != nil {
			return fmt.Errorf("aws profile %s: %w", name, err)
		}
		key := old[name]
		if key.ID == "" {
			var b [30]byte
			if _, err := rand.Read(b[:]); err != nil {
				return err
			}
			key = issuedKey{ID: "SB" + strings.ToUpper(base64.RawURLEncoding.EncodeToString(b[:16])), Secret: base64.StdEncoding.EncodeToString(b[:])}
		}
		keys[name] = key
		section := "profile " + name
		if name == "default" {
			section = "default"
		}
		region := regions[name]
		if region == "" {
			region = "us-east-1"
		}
		fmt.Fprintf(&config, "[%s]\nendpoint_url = https://%s\nca_bundle = /root/.aws/ca.pem\nregion = %s\n\n", section, net.JoinHostPort(p.host, strconv.Itoa(port)), region)
		fmt.Fprintf(&credentials, "[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n\n", name, key.ID, key.Secret)
	}
	cert, err := p.certificate()
	if err != nil {
		return err
	}
	awsDir := filepath.Join(dir, ".aws")
	if err := util.WriteFileAtomic(filepath.Join(awsDir, "ca.pem"), 0o600, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})); err != nil {
		return err
	}
	if err := util.WriteFileAtomic(filepath.Join(awsDir, "credentials"), 0o600, []byte(credentials.String())); err != nil {
		return err
	}
	if err := util.WriteFileAtomic(filepath.Join(awsDir, "config"), 0o600, []byte(config.String())); err != nil {
		return err
	}
	p.mu.Lock()
	p.keys = keys
	p.sessions = map[string]session{}
	p.generation++
	p.mu.Unlock()
	return nil
}
