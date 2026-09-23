package sshproxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hrntknr/sb/internal/util"
	knownhostsdb "github.com/skeema/knownhosts"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// configureHostKey verifies upstream host keys against the user's ssh
// known_hosts, honoring the ssh config. Matching (and accept-new recording)
// is keyed by HostKeyAlias when set, like ssh, and the resolved HostName
// otherwise. "no" disables verification; "accept-new" trusts unknown keys on
// first use and records them; anything else (including the default "ask",
// which cannot prompt here) requires the key to be already known.
// KnownHostsCommand is not supported and fails closed.
func configureHostKey(config sshConfig, client *cryptossh.ClientConfig) error {
	if config.KnownHostsCommand != "" {
		return fmt.Errorf("ssh: knownhostscommand is not supported; verify via known_hosts files or set strict-host-key-checking=no")
	}
	if strings.ToLower(strings.TrimSpace(config.StrictHostKeyChecking)) == "no" {
		client.HostKeyCallback = cryptossh.InsecureIgnoreHostKey()
		return nil
	}
	db, err := knownhostsdb.NewDB(existingKnownHostsFiles(config)...)
	if err != nil {
		return err
	}
	known := db.HostKeyCallback()
	matchAddr := config.matchAddr()
	supported := cryptossh.SupportedAlgorithms().HostKeys
	for _, key := range db.HostKeys(matchAddr) {
		if key.Cert {
			// A CA can sign host keys of any type, independently of its own key type.
			for _, algorithm := range supported {
				if strings.Contains(algorithm, "-cert-") {
					client.HostKeyAlgorithms = append(client.HostKeyAlgorithms, algorithm)
				}
			}
			break
		}
	}
	for _, algorithm := range db.HostKeyAlgorithms(matchAddr) {
		if slices.Contains(supported, algorithm) && !slices.Contains(client.HostKeyAlgorithms, algorithm) {
			client.HostKeyAlgorithms = append(client.HostKeyAlgorithms, algorithm)
		}
	}
	for _, algorithm := range supported {
		if !slices.Contains(client.HostKeyAlgorithms, algorithm) {
			client.HostKeyAlgorithms = append(client.HostKeyAlgorithms, algorithm)
		}
	}
	recordPath := recordableKnownHostsFile(config)
	acceptNew := strings.ToLower(strings.TrimSpace(config.StrictHostKeyChecking)) == "accept-new"
	client.HostKeyCallback = func(_ string, remote net.Addr, key cryptossh.PublicKey) error {
		err := known(matchAddr, remote, key)
		if err == nil {
			return nil
		}
		if !acceptNew || !isUnknownHost(err) {
			return fmt.Errorf("host key verification failed for %s: %w", matchAddr, err)
		}
		if recordPath == "" {
			return fmt.Errorf("host key verification failed for %s: no user known_hosts file to record the key in", matchAddr)
		}
		if err := appendKnownHost(recordPath, matchAddr, key); err != nil {
			return fmt.Errorf("host key verification failed for %s: %w", matchAddr, err)
		}
		return nil
	}
	return nil
}

// isUnknownHost reports whether the error is an unknown-host KeyError (no
// key recorded yet), as opposed to a key mismatch.
func isUnknownHost(err error) bool {
	var keyErr *knownhosts.KeyError
	return errors.As(err, &keyErr) && len(keyErr.Want) == 0
}

func existingKnownHostsFiles(config sshConfig) []string {
	var files []string
	for _, path := range append(config.GlobalKnownHosts, config.UserKnownHosts...) {
		path = util.ExpandHome(path)
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	return files
}

// recordableKnownHostsFile returns the user known_hosts file that
// newly-trusted keys are recorded in.
func recordableKnownHostsFile(config sshConfig) string {
	if len(config.UserKnownHosts) == 0 {
		return ""
	}
	return util.ExpandHome(config.UserKnownHosts[0])
}

// appendKnownHost records a first-seen host key, mirroring ssh's accept-new.
func appendKnownHost(path, matchAddr string, key cryptossh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, knownhosts.Line([]string{matchAddr}, key)); err != nil {
		return err
	}
	return f.Sync()
}
