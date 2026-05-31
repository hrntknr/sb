package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/hrntknr/secretbridge/pkg/proxy"
	proxyk8s "github.com/hrntknr/secretbridge/pkg/proxy/k8s"
	proxyssh "github.com/hrntknr/secretbridge/pkg/proxy/ssh"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultSSHPort = 2222
	defaultK8sPort = 6443
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
	cmd.Flags().StringVar(&configPath, "config", "config.yaml", "config yaml path")
	cmd.Flags().StringVar(&host, "host", string(proxy.DefaultProxyHost), "host written into generated config")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	cmd.Flags().StringVar(&sshListen, "ssh-listen", fmt.Sprintf(":%d", defaultSSHPort), "ssh listen address")
	cmd.Flags().StringVar(&k8sListen, "k8s-listen", fmt.Sprintf(":%d", defaultK8sPort), "k8s listen address")

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
	sshPort, err := listenPort(sshListen)
	if err != nil {
		return fmt.Errorf("parse ssh listen address: %w", err)
	}
	k8sPort, err := listenPort(k8sListen)
	if err != nil {
		return fmt.Errorf("parse k8s listen address: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 3)
	go func() {
		errc <- bundle.SyncConfig(ctx, proxy.ProxyHost(host), proxy.Ports{SSH: sshPort, K8s: k8sPort}, dir)
	}()
	go serve(ctx, errc, sshListen, bundle.SSH.Serve)
	go serve(ctx, errc, k8sListen, bundle.K8s.Serve)

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
	case "debug":
		level = slog.LevelDebug
	case "", "info":
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

func listenPort(addr string) (int, error) {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0, err
	}
	if port <= 0 {
		return 0, fmt.Errorf("port must be greater than 0")
	}
	return port, nil
}

func readConfig(path string) (proxy.Config, error) {
	var raw struct {
		SSH []string `yaml:"ssh"`
		K8s []string `yaml:"k8s"`
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return proxy.Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return proxy.Config{}, fmt.Errorf("parse config: %w", err)
	}

	config := proxy.Config{
		SSH: make(proxyssh.Targets, 0, len(raw.SSH)),
		K8s: make(proxyk8s.Targets, 0, len(raw.K8s)),
	}
	for _, item := range raw.SSH {
		args, err := parseAllow(item, 1)
		if err != nil {
			return proxy.Config{}, fmt.Errorf("parse ssh target %q: %w", item, err)
		}
		config.SSH = append(config.SSH, args[0])
	}
	for _, item := range raw.K8s {
		args, err := parseAllow(item, 2)
		if err != nil {
			return proxy.Config{}, fmt.Errorf("parse k8s target %q: %w", item, err)
		}
		verb := proxyk8s.Verb(args[0])
		switch verb {
		case proxyk8s.Read, proxyk8s.ReadWrite:
		default:
			return proxy.Config{}, fmt.Errorf("parse k8s target %q: invalid verb", item)
		}
		config.K8s = append(config.K8s, proxyk8s.Target{Verb: verb, Context: args[1]})
	}
	return config, nil
}

func parseAllow(s string, want int) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "allow(") || !strings.HasSuffix(s, ")") {
		return nil, fmt.Errorf("want allow(...)")
	}
	fields := strings.Split(strings.TrimSuffix(strings.TrimPrefix(s, "allow("), ")"), ",")
	if len(fields) != want {
		return nil, fmt.Errorf("want %d args", want)
	}
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
		if fields[i] == "" {
			return nil, fmt.Errorf("empty arg")
		}
	}
	return fields, nil
}

func serve(ctx context.Context, errc chan<- error, addr string, serve func(net.Listener) error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		errc <- err
		return
	}
	slog.Info("listening", "addr", addr)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	if err := serve(listener); err != nil && ctx.Err() == nil {
		errc <- err
	}
}
