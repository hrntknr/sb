package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/hrntknr/secretbridge/pkg/proxy"
	proxyk8s "github.com/hrntknr/secretbridge/pkg/proxy/k8s"
	proxyssh "github.com/hrntknr/secretbridge/pkg/proxy/ssh"
	"github.com/hrntknr/secretbridge/pkg/util"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigDir     = "secretbridge"
	defaultConfigFile    = "config.yaml"
	defaultSSHListenAddr = ":0"
	defaultK8sListenAddr = ":0"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var (
		configPath string
		host       string
		logLevel   string
		sshListen  string
		k8sListen  string
	)

	cmd := &cobra.Command{
		Use:          "secretbridge [flags] <dir>",
		Short:        "Run secretbridge proxy",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), configPath, host, logLevel, sshListen, k8sListen, args[0])
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath(), "config yaml path")
	cmd.Flags().StringVar(&host, "host", string(proxy.DefaultProxyHost), "host written into generated config")
	cmd.Flags().StringVar(&logLevel, "log-level", "silent", "log level: silent, debug, info, warn, error")
	cmd.Flags().StringVar(&sshListen, "ssh-listen", defaultSSHListenAddr, "ssh listen address")
	cmd.Flags().StringVar(&k8sListen, "k8s-listen", defaultK8sListenAddr, "k8s listen address")

	return cmd
}

func run(ctx context.Context, configPath, host, logLevel, sshListen, k8sListen, dir string) error {
	if err := configureLogger(logLevel); err != nil {
		return err
	}
	slog.Info("starting secretbridge", "config", configPath, "host", host, "ssh_listen", sshListen, "k8s_listen", k8sListen, "dir", dir)
	config, err := readConfig(configPath)
	if err != nil {
		return err
	}
	slog.Debug("loaded config", "ssh_targets", len(config.SSH), "k8s_targets", len(config.K8s))
	bundle := &proxy.Bundle{
		SSH: proxyssh.New(config.SSH),
		K8s: proxyk8s.New(config.K8s),
	}

	sshListener, err := net.Listen("tcp", sshListen)
	if err != nil {
		return fmt.Errorf("listen ssh: %w", err)
	}
	k8sListener, err := net.Listen("tcp", k8sListen)
	if err != nil {
		_ = sshListener.Close()
		return fmt.Errorf("listen k8s: %w", err)
	}
	sshPort, err := listenerPort(sshListener)
	if err != nil {
		_ = sshListener.Close()
		_ = k8sListener.Close()
		return fmt.Errorf("resolve ssh listen port: %w", err)
	}
	k8sPort, err := listenerPort(k8sListener)
	if err != nil {
		_ = sshListener.Close()
		_ = k8sListener.Close()
		return fmt.Errorf("resolve k8s listen port: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 3)
	go func() {
		errc <- bundle.SyncConfig(ctx, proxy.ProxyHost(host), proxy.Ports{SSH: sshPort, K8s: k8sPort}, dir)
	}()
	go serve(ctx, errc, sshListener, bundle.SSH.Serve)
	go serve(ctx, errc, k8sListener, bundle.K8s.Serve)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		stop()
		return err
	}
}

func configureLogger(levelText string) error {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelText)) {
	case "", "silent":
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(1000)})))
		return nil
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q", levelText)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return defaultConfigFile
	}
	return filepath.Join(dir, defaultConfigDir, defaultConfigFile)
}

func listenerPort(listener net.Listener) (int, error) {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("listener address is %T, want *net.TCPAddr", listener.Addr())
	}
	if addr.Port <= 0 {
		return 0, fmt.Errorf("port must be greater than 0")
	}
	return addr.Port, nil
}

type rawConfig struct {
	SSH []rawSSHTarget `yaml:"ssh"`
	K8s []rawK8sTarget `yaml:"k8s"`
}

type rawSSHTarget struct {
	Host     string   `yaml:"host"`
	Commands []string `yaml:"commands"`
}

type rawK8sTarget struct {
	Cluster   string `yaml:"cluster"`
	Mode      string `yaml:"mode"`
	Namespace string `yaml:"namespace"`
}

func readConfig(path string) (proxy.Config, error) {
	path = util.ExpandHome(path)
	config, err := readConfigFile(path)
	if err != nil {
		return proxy.Config{}, err
	}
	if err := mergeConfDir(filepath.Join(filepath.Dir(path), "conf.d"), &config); err != nil {
		return proxy.Config{}, err
	}
	return config, nil
}

func readConfigFile(path string) (proxy.Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return proxy.Config{}, fmt.Errorf("read config: %w", err)
	}
	return parseConfig(content)
}

func parseConfig(content []byte) (proxy.Config, error) {
	var raw rawConfig
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return proxy.Config{}, fmt.Errorf("parse config: %w", err)
	}
	return buildConfig(raw)
}

func buildConfig(raw rawConfig) (proxy.Config, error) {
	var config proxy.Config
	config.SSH = make(proxyssh.Targets, 0, len(raw.SSH))
	config.K8s = make(proxyk8s.Targets, 0, len(raw.K8s))
	for i, item := range raw.SSH {
		if strings.TrimSpace(item.Host) == "" {
			return proxy.Config{}, fmt.Errorf("ssh target %d: host is required", i)
		}
		target := proxyssh.Target{Host: item.Host}
		if len(item.Commands) > 0 {
			target.Commands = item.Commands
		} else {
			target.Commands = []string{"*"}
			target.Shell = true
			target.Forward = true
		}
		config.SSH = append(config.SSH, target)
	}
	for i, item := range raw.K8s {
		if strings.TrimSpace(item.Cluster) == "" {
			return proxy.Config{}, fmt.Errorf("k8s target %d: cluster is required", i)
		}
		mode := proxyk8s.Verb(item.Mode)
		switch mode {
		case proxyk8s.Read, proxyk8s.ReadWrite:
		default:
			return proxy.Config{}, fmt.Errorf("k8s target %d: invalid mode %q", i, item.Mode)
		}
		target := proxyk8s.Target{Mode: mode, Cluster: item.Cluster}
		if namespace := strings.TrimSpace(item.Namespace); namespace != "" {
			target.Namespaces = []string{namespace}
		} else {
			target.ClusterScope = true
		}
		config.K8s = append(config.K8s, target)
	}
	return config, nil
}

func mergeConfDir(dir string, dst *proxy.Config) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read conf.d: %w", err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		extra, err := readConfigFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("conf.d/%s: %w", name, err)
		}
		mergeTargets(dst, extra)
	}
	return nil
}

func mergeTargets(dst *proxy.Config, src proxy.Config) {
	for _, t := range src.SSH {
		if i := findSSHTarget(dst.SSH, t.Host); i >= 0 {
			dst.SSH[i] = t
		} else {
			dst.SSH = append(dst.SSH, t)
		}
	}
	for _, t := range src.K8s {
		if i := findK8sTarget(dst.K8s, t.Cluster); i >= 0 {
			dst.K8s[i] = t
		} else {
			dst.K8s = append(dst.K8s, t)
		}
	}
}

func findSSHTarget(targets proxyssh.Targets, host string) int {
	for i, t := range targets {
		if t.Host == host {
			return i
		}
	}
	return -1
}

func findK8sTarget(targets proxyk8s.Targets, cluster string) int {
	for i, t := range targets {
		if t.Cluster == cluster {
			return i
		}
	}
	return -1
}

func serve(ctx context.Context, errc chan<- error, listener net.Listener, serve func(net.Listener) error) {
	slog.Info("listening", "addr", listener.Addr().String())
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	if err := serve(listener); err != nil && ctx.Err() == nil {
		errc <- err
	}
}
