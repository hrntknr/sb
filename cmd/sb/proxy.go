package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hrntknr/sb/internal/agentenv"
	"github.com/hrntknr/sb/internal/config"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/sshproxy"
	"github.com/spf13/cobra"
)

// newProxyCommand builds `sb proxy <dir>`: the credential proxy
// without any container management.
func newProxyCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "proxy <dir>",
		Short:         "Run the credential proxy, writing .ssh and .kube under dir",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := configureLogger(opts.logLevel); err != nil {
				return err
			}
			slog.Info("starting sb proxy", "config", opts.configPath, "host", opts.host, "ssh_listen", opts.sshListen, "k8s_listen", opts.k8sListen, "dir", args[0])
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			proxy, err := startProxy(ctx, *opts, opts.host, args[0])
			if err != nil {
				return err
			}
			return proxy.Wait()
		},
	}
	cmd.Flags().StringVar(&opts.host, "host", "localhost", "host written into generated config (also covered by the k8s proxy certificate)")
	cmd.Flags().StringVar(&opts.sshListen, "ssh-listen", defaultListenAddr, "ssh listen address")
	cmd.Flags().StringVar(&opts.k8sListen, "k8s-listen", defaultListenAddr, "k8s listen address")
	return cmd
}

// startProxy starts the ssh and k8s proxies serving credentials under dir
// and returns once those credentials are on disk. host is the address
// containers use to reach the proxy (from ResolveHost, or the proxy
// command's --host flag). Cancel ctx to stop them.
func startProxy(ctx context.Context, opts options, host, dir string) (*proxyServer, error) {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return nil, err
	}
	sshProxy := sshproxy.New(cfg.SSH, agentenv.Source{Path: cfg.Proxy.SSHAgentEnv}.SocketPath)
	k8sProxy := k8sproxy.New(cfg.K8s, host)

	sshListener, k8sListener, err := listen(opts.sshListen, opts.k8sListen)
	if err != nil {
		return nil, err
	}
	if err := sshProxy.WriteConfig(host, listenerPort(sshListener), dir); err != nil {
		return nil, err
	}

	server := &proxyServer{ctx: ctx, errc: make(chan error, 4)}
	// The k8s proxy signals once its kubeconfig (with this process's
	// certificate) is on disk, so the first request finds valid tokens.
	ready := make(chan struct{})
	go func() {
		server.errc <- k8sProxy.SyncConfig(ctx, listenerPort(k8sListener), dir, ready)
	}()
	select {
	case <-ready:
	case err := <-server.errc:
		return nil, err
	}
	go serve(ctx, server.errc, sshListener, sshProxy.Serve)
	go serve(ctx, server.errc, k8sListener, k8sProxy.Serve)
	go func() {
		server.errc <- config.Watch(ctx, opts.configPath, func(cfg config.Config) {
			sshProxy.SetTargets(cfg.SSH)
			k8sProxy.SetTargets(cfg.K8s)
		})
	}()
	return server, nil
}

// proxyServer runs the proxy components on background goroutines until ctx
// is cancelled or one of them fails.
type proxyServer struct {
	ctx  context.Context
	errc chan error
}

// Wait blocks until the proxies stop: nil after cancellation, otherwise the
// failing component's error.
func (s *proxyServer) Wait() error {
	select {
	case <-s.ctx.Done():
		return nil
	case err := <-s.errc:
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
