package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrntknr/secretbridge/internal/agentenv"
	"github.com/hrntknr/secretbridge/internal/config"
	"github.com/hrntknr/secretbridge/internal/k8sproxy"
	"github.com/hrntknr/secretbridge/internal/sshproxy"
	"github.com/spf13/cobra"
)

const (
	defaultConfigDir  = "secretbridge"
	defaultConfigFile = "config.yaml"
	defaultListenAddr = ":0"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	configPath string
	host       string
	logLevel   string
	sshListen  string
	k8sListen  string
	agentEnv   agentenv.Source
}

func newRootCommand() *cobra.Command {
	var (
		opts        options
		sshAgentEnv string
	)

	cmd := &cobra.Command{
		Use:          "secretbridge [flags] <dir>",
		Short:        "Run secretbridge proxy",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.agentEnv = agentenv.Source{Path: sshAgentEnv}
			return run(cmd.Context(), opts, args[0])
		},
	}
	cmd.Flags().StringVar(&opts.configPath, "config", defaultConfigPath(), "config yaml path")
	cmd.Flags().StringVar(&opts.host, "host", "localhost", "host written into generated config (also covered by the k8s proxy certificate)")
	cmd.Flags().StringVar(&opts.logLevel, "log-level", "silent", "log level: silent, debug, info, warn, error")
	cmd.Flags().StringVar(&opts.sshListen, "ssh-listen", defaultListenAddr, "ssh listen address")
	cmd.Flags().StringVar(&opts.k8sListen, "k8s-listen", defaultListenAddr, "k8s listen address")
	cmd.Flags().StringVar(&sshAgentEnv, "ssh-agent-env", "", "env file exporting SSH_AUTH_SOCK (shell source, e.g. ssh-agent output), re-read on every upstream connection")
	return cmd
}

func run(ctx context.Context, opts options, dir string) error {
	if err := configureLogger(opts.logLevel); err != nil {
		return err
	}
	slog.Info("starting secretbridge", "config", opts.configPath, "host", opts.host, "ssh_listen", opts.sshListen, "k8s_listen", opts.k8sListen, "dir", dir)
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	sshProxy := sshproxy.New(cfg.SSH, opts.agentEnv.SocketPath)
	k8sProxy := k8sproxy.New(cfg.K8s, opts.host)

	sshListener, k8sListener, err := listen(opts.sshListen, opts.k8sListen)
	if err != nil {
		return err
	}
	if err := sshProxy.WriteConfig(opts.host, listenerPort(sshListener), dir); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The k8s proxy signals once its kubeconfig (with this process's
	// certificate) is on disk, so the first request finds valid tokens.
	ready := make(chan struct{})
	errc := make(chan error, 3)
	go func() {
		errc <- k8sProxy.SyncConfig(ctx, listenerPort(k8sListener), dir, ready)
	}()
	select {
	case <-ready:
	case err := <-errc:
		return err
	}
	go serve(ctx, errc, sshListener, sshProxy.Serve)
	go serve(ctx, errc, k8sListener, k8sProxy.Serve)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		stop()
		return err
	}
}

func listen(sshAddr, k8sAddr string) (ssh, k8s net.Listener, err error) {
	ssh, err = net.Listen("tcp", sshAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen ssh: %w", err)
	}
	k8s, err = net.Listen("tcp", k8sAddr)
	if err != nil {
		ssh.Close()
		return nil, nil, fmt.Errorf("listen k8s: %w", err)
	}
	return ssh, k8s, nil
}

func listenerPort(l net.Listener) int {
	return l.Addr().(*net.TCPAddr).Port
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
