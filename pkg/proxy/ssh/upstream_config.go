package ssh

import (
	"log/slog"
	"os/exec"
	"os/user"
	"strings"
)

func upstreamConfig(username, host, port string) (sshConfig, error) {
	args := []string{"-G"}
	if username != "" && username != defaultUserMarker {
		args = append(args, "-l", username)
	}
	args = append(args, host)
	slog.Debug("loading ssh config", "host", host)
	output, err := exec.Command("ssh", args...).Output()
	if err != nil {
		return sshConfig{}, err
	}

	config := parseSSHConfig(output)
	if config.Host == "" {
		config.Host = host
	}
	if config.User == "" || config.User == defaultUserMarker {
		config.User = currentUsername(config.User)
	}
	if username != "" && username != defaultUserMarker {
		config.User = username
	}
	if config.Port == "" {
		config.Port = port
	}
	slog.Debug("resolved ssh config", "user", config.User, "host", config.Host, "port", config.Port, "identity_files", len(config.IdentityFiles), "certificate_files", len(config.CertificateFiles), "identities_only", config.IdentitiesOnly, "proxy_command", config.ProxyCommand != "")
	return config, nil
}

func parseSSHConfig(output []byte) sshConfig {
	var config sshConfig
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "hostname":
			config.Host = value
		case "user":
			config.User = value
		case "port":
			config.Port = value
		case "identityfile":
			if value != "" && value != "none" {
				config.IdentityFiles = append(config.IdentityFiles, value)
			}
		case "certificatefile":
			if value != "" && value != "none" {
				config.CertificateFiles = append(config.CertificateFiles, value)
			}
		case "proxycommand":
			config.ProxyCommand = value
		case "identitiesonly":
			config.IdentitiesOnly = strings.EqualFold(value, "yes")
		}
	}
	return config
}

func currentUsername(fallback string) string {
	if current, err := user.Current(); err == nil {
		if current.Username != "" {
			return current.Username
		}
	}
	return fallback
}
