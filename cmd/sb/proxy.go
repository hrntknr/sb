package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/hrntknr/sb/internal/awsproxy"
	v3 "github.com/hrntknr/sb/internal/config/v3"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/sshproxy"
	"github.com/spf13/cobra"
)

// newProxyCommand builds `sb proxy <dir>`: the credential proxy without
// any container management, for manual downstreams.
func newProxyCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "proxy <dir>",
		Short:         "Run the credential proxy, writing .ssh, .kube and .aws under dir",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := configureLogger(opts.logLevel); err != nil {
				return err
			}
			if err := requireEmptyDir(args[0]); err != nil {
				return err
			}
			cfg, err := v3.Load(opts.configPath)
			if err != nil {
				return err
			}
			slog.Info("starting sb proxy", "config", opts.configPath, "host", opts.host, "ssh_listen", opts.sshListen, "k8s_listen", opts.k8sListen, "aws_listen", opts.awsListen, "dir", args[0])
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			proxy, err := startProxy(ctx, cfg, *opts, opts.host, args[0])
			if err != nil {
				return err
			}
			err = proxy.Wait()
			// The stop flow is the same on every exit: the proxies' open
			// connections are closed within the deadline, then the issued
			// credentials are gone.
			proxy.Shutdown(shutdownCtx())
			removeIssued(args[0])
			return err
		},
	}
	cmd.Flags().StringVar(&opts.host, "host", "localhost", "host written into generated config (also covered by the k8s proxy certificate)")
	cmd.Flags().StringVar(&opts.sshListen, "ssh-listen", defaultListenAddr, "ssh listen address")
	cmd.Flags().StringVar(&opts.k8sListen, "k8s-listen", defaultListenAddr, "k8s listen address")
	cmd.Flags().StringVar(&opts.awsListen, "aws-listen", defaultListenAddr, "aws listen address")
	return cmd
}

// requireEmptyDir rejects a dir that holds anything: the proxy requires a
// dedicated empty directory, so its credentials are never mixed with (or
// written over) someone else's files.
func requireEmptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // issuing the credentials creates it
		}
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("proxy: %s holds %d entries; give sb a dedicated empty directory", dir, len(entries))
	}
	return nil
}

// removeIssued deletes the credentials sb issued under dir: the .ssh,
// .kube, and .aws subtrees. Anything else in dir is not sb's to delete.
func removeIssued(dir string) {
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			slog.Warn("proxy stop: remove issued", "dir", filepath.Join(dir, name), "error", err)
		}
	}
}

// startProxy starts the ssh, k8s and AWS proxies serving credentials under
// dir and returns once those credentials are on disk. host is the address
// downstreams use to reach the proxy. Cancel ctx to stop them.
func startProxy(ctx context.Context, cfg v3.Config, opts options, host, dir string) (*proxyServer, error) {
	sshProxy := sshproxy.New(cfg.SSHTargets(), nil)
	k8sProxy := k8sproxy.New(cfg.K8sTargets(), host)
	awsProxy := awsproxy.New(cfg.AWSTargets(), host)

	sshListener, k8sListener, err := listen(opts.sshListen, opts.k8sListen)
	if err != nil {
		return nil, err
	}
	awsListener, err := net.Listen("tcp", opts.awsListen)
	if err != nil {
		sshListener.Close()
		k8sListener.Close()
		return nil, fmt.Errorf("listen aws: %w", err)
	}
	if err := sshProxy.WriteConfig(host, listenerPort(sshListener), dir); err != nil {
		return nil, err
	}

	server := &proxyServer{ctx: ctx, errc: make(chan error, 6), ssh: sshProxy, k8s: k8sProxy, aws: awsProxy}
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
	awsReady := make(chan error, 1)
	go func() { server.errc <- awsProxy.SyncConfig(ctx, listenerPort(awsListener), dir, awsReady) }()
	select {
	case err := <-awsReady:
		if err != nil {
			sshListener.Close()
			k8sListener.Close()
			awsListener.Close()
			return nil, err
		}
	case err := <-server.errc:
		return nil, err
	}
	go serve(ctx, server.errc, sshListener, sshProxy.Serve)
	go serve(ctx, server.errc, k8sListener, k8sProxy.Serve)
	go serve(ctx, server.errc, awsListener, awsProxy.Serve)
	return server, nil
}

// proxyServer runs the proxy components on background goroutines until ctx
// is cancelled or one of them fails.
type proxyServer struct {
	ctx  context.Context
	errc chan error
	ssh  *sshproxy.Proxy
	k8s  *k8sproxy.Proxy
	aws  *awsproxy.Proxy
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

// Shutdown stops the proxies' downstream connections: new requests are
// rejected, open ones (SSH transfers, k8s watches, logs -f) are closed,
// and each proxy waits for its cleanup within ctx's deadline.
func (s *proxyServer) Shutdown(ctx context.Context) {
	s.ssh.Shutdown(ctx)
	s.k8s.Shutdown(ctx)
	s.aws.Shutdown(ctx)
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
