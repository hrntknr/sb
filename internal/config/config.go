// Package config loads the secretbridge policy config, merging drop-in files
// from a conf.d directory next to the main config.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hrntknr/secretbridge/internal/k8sproxy"
	"github.com/hrntknr/secretbridge/internal/sshproxy"
	"github.com/hrntknr/secretbridge/internal/util"
	"gopkg.in/yaml.v3"
)

// Config is the merged policy for the ssh and k8s proxies.
type Config struct {
	SSH []sshproxy.Target
	K8s []k8sproxy.Target
}

type file struct {
	SSH []sshTarget `yaml:"ssh"`
	K8s []k8sTarget `yaml:"k8s"`
}

type sshTarget struct {
	Host     string   `yaml:"host"`
	Commands []string `yaml:"commands"`
}

type k8sTarget struct {
	Context   string `yaml:"context"`
	Mode      string `yaml:"mode"`
	Namespace string `yaml:"namespace"`
}

// Load reads path and merges any conf.d/*.yaml (or *.yml) files placed next to
// it. Later files override targets with the same host (ssh) or context (k8s)
// and append new ones.
func Load(path string) (Config, error) {
	path = util.ExpandHome(path)
	config, err := loadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := mergeConfDir(filepath.Join(filepath.Dir(path), "conf.d"), &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func loadFile(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var f file
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return build(f)
}

func build(f file) (Config, error) {
	ssh := make([]sshproxy.Target, 0, len(f.SSH))
	for i, item := range f.SSH {
		if strings.TrimSpace(item.Host) == "" {
			return Config{}, fmt.Errorf("ssh target %d: host is required", i)
		}
		target := sshproxy.Target{Host: item.Host}
		if len(item.Commands) > 0 {
			target.Commands = item.Commands
		} else {
			// No command restriction: allow everything including shell and
			// port forwarding.
			target.Commands = []string{"*"}
			target.Shell = true
			target.Forward = true
		}
		ssh = append(ssh, target)
	}

	k8s := make([]k8sproxy.Target, 0, len(f.K8s))
	for i, item := range f.K8s {
		if strings.TrimSpace(item.Context) == "" {
			return Config{}, fmt.Errorf("k8s target %d: context is required", i)
		}
		var mode k8sproxy.Verb
		switch item.Mode {
		case "r":
			mode = k8sproxy.Read
		case "rw":
			mode = k8sproxy.ReadWrite
		default:
			return Config{}, fmt.Errorf("k8s target %d: invalid mode %q", i, item.Mode)
		}
		target := k8sproxy.Target{Mode: mode, Context: item.Context}
		if namespace := strings.TrimSpace(item.Namespace); namespace != "" {
			target.Namespaces = []string{namespace}
		} else {
			target.ClusterScope = true
		}
		k8s = append(k8s, target)
	}
	return Config{SSH: ssh, K8s: k8s}, nil
}

func mergeConfDir(dir string, dst *Config) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read conf.d: %w", err)
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".yml" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		extra, err := loadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("conf.d/%s: %w", name, err)
		}
		merge(dst, extra)
	}
	return nil
}

func merge(dst *Config, src Config) {
	for _, target := range src.SSH {
		if i := findSSH(dst.SSH, target.Host); i >= 0 {
			dst.SSH[i] = target
		} else {
			dst.SSH = append(dst.SSH, target)
		}
	}
	for _, target := range src.K8s {
		if i := findK8s(dst.K8s, target.Context); i >= 0 {
			dst.K8s[i] = target
		} else {
			dst.K8s = append(dst.K8s, target)
		}
	}
}

func findSSH(targets []sshproxy.Target, host string) int {
	for i, target := range targets {
		if target.Host == host {
			return i
		}
	}
	return -1
}

func findK8s(targets []k8sproxy.Target, context string) int {
	for i, target := range targets {
		if target.Context == context {
			return i
		}
	}
	return -1
}
