package sshproxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrntknr/sb/internal/util"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback verifies upstream host keys against the user's ssh
// known_hosts, honoring the ssh config. Matching (and accept-new recording)
// is keyed by HostKeyAlias when set, like ssh, and the resolved HostName
// otherwise. "no" disables verification; "accept-new" trusts unknown keys on
// first use and records them; anything else (including the default "ask",
// which cannot prompt here) requires the key to be already known.
// KnownHostsCommand is not supported and fails closed.
func hostKeyCallback(config sshConfig) (cryptossh.HostKeyCallback, error) {
	if config.KnownHostsCommand != "" {
		return nil, fmt.Errorf("ssh: knownhostscommand is not supported; verify via known_hosts files or set strict-host-key-checking=no")
	}
	if strings.ToLower(strings.TrimSpace(config.StrictHostKeyChecking)) == "no" {
		return cryptossh.InsecureIgnoreHostKey(), nil
	}
	known, err := knownhosts.New(existingKnownHostsFiles(config)...)
	if err != nil {
		return nil, err
	}
	matchAddr := config.matchAddr()
	recordPath := recordableKnownHostsFile(config)
	acceptNew := strings.ToLower(strings.TrimSpace(config.StrictHostKeyChecking)) == "accept-new"
	return func(_ string, remote net.Addr, key cryptossh.PublicKey) error {
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
	}, nil
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
