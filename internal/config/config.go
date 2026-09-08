// Package config loads the sb policy config, merging drop-in files
// from a conf.d directory next to the main config.
package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/sshproxy"
	"github.com/hrntknr/sb/internal/util"
	"gopkg.in/yaml.v3"
)

// Config is the merged policy for the ssh and k8s proxies and the
// container settings for `sb run`.
type Config struct {
	SSH []sshproxy.Target
	K8s []k8sproxy.Target
	// Container configures how `sb run` launches the container.
	Container Container
}

// Container is the `container` section of the config.
type Container struct {
	// Runtime selects docker, podman, or apple for `sb run`;
	// empty or "auto" auto-detects. The --runtime flag overrides it.
	Runtime string
	// Image, when set, is the image `sb run` starts; its
	// arguments then form the container command.
	Image string
	// Mounts are extra "source:target" volumes, with ~ expanded in the
	// source.
	Mounts []string
}

type file struct {
	SSH       []sshTarget    `yaml:"ssh"`
	K8s       []k8sTarget    `yaml:"k8s"`
	Container *containerFile `yaml:"container"`
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

type containerFile struct {
	Runtime string   `yaml:"runtime"`
	Image   string   `yaml:"image"`
	Mounts  []string `yaml:"mounts"`
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

// Watch calls onChange with the current config, then again whenever path or
// its conf.d files change. A reload that fails (e.g. invalid yaml) keeps the
// previous config; the next change retries.
func Watch(ctx context.Context, path string, onChange func(Config)) error {
	path = util.ExpandHome(path)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watch config: %w", err)
	}
	defer watcher.Close()
	// The config directory also carries the conf.d creation when conf.d
	// does not exist yet; files inside it need their own watch.
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return fmt.Errorf("watch config dir: %w", err)
	}
	if err := watcher.Add(confDir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("watch config conf.d: %w", err)
	}
	reload(path, onChange)
	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			if event.Op&fsnotify.Create != 0 && filepath.Clean(event.Name) == filepath.Clean(confDir(path)) {
				_ = watcher.Add(confDir(path))
			}
			reload(path, onChange)
		case err := <-watcher.Errors:
			return err
		}
	}
}

func confDir(path string) string {
	return filepath.Join(filepath.Dir(path), "conf.d")
}

func reload(path string, onChange func(Config)) {
	config, err := Load(path)
	if err != nil {
		slog.Warn("config reload failed; keeping previous config", "error", err)
		return
	}
	onChange(config)
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

	var container Container
	if f.Container != nil {
		container.Runtime = strings.TrimSpace(f.Container.Runtime)
		switch container.Runtime {
		case "", "auto", "docker", "podman", "apple":
		default:
			return Config{}, fmt.Errorf("container runtime: unknown runtime %q (want docker, podman, or apple)", container.Runtime)
		}
		container.Image = strings.TrimSpace(f.Container.Image)
		container.Mounts = make([]string, 0, len(f.Container.Mounts))
		for i, item := range f.Container.Mounts {
			source, target, found := strings.Cut(item, ":")
			source = util.ExpandHome(source)
			if !found || strings.TrimSpace(source) == "" || strings.TrimSpace(target) == "" {
				return Config{}, fmt.Errorf("mount %d: want <source>:<target>, got %q", i, item)
			}
			if !filepath.IsAbs(source) {
				return Config{}, fmt.Errorf("mount %d: source must be an absolute path: %q", i, source)
			}
			if !filepath.IsAbs(target) {
				return Config{}, fmt.Errorf("mount %d: target must be an absolute path: %q", i, target)
			}
			container.Mounts = append(container.Mounts, source+":"+target)
		}
	}
	return Config{SSH: ssh, K8s: k8s, Container: container}, nil
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
	if src.Container.Runtime != "" {
		dst.Container.Runtime = src.Container.Runtime
	}
	if src.Container.Image != "" {
		dst.Container.Image = src.Container.Image
	}
	for _, mount := range src.Container.Mounts {
		if !slices.Contains(dst.Container.Mounts, mount) {
			dst.Container.Mounts = append(dst.Container.Mounts, mount)
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
