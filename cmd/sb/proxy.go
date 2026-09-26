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
				// Half of the credentials may be on disk already; nothing
				// sb issued stays behind a failed start.
				removeIssued(args[0])
				return err
			}
			err = proxy.Wait()
			// The stop flow is the same on every exit: the proxies stop
			// accepting and cancel their upstreams within the deadline,
			// then the issued credentials are gone.
			proxy.Stop(shutdownCtx())
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
// dir, and returns once every issuance is on disk: the ssh config and keys
// (written synchronously), the k8s and AWS credentials (their ready channel
// carries the initial write's own result — nil is a success). Every failure
// path closes the listeners. host is the address downstreams use to reach
// the proxy. Cancel ctx to stop them.
func startProxy(ctx context.Context, cfg v3.Config, opts options, host, dir string) (*proxyServer, error) {
	sshProxy := sshproxy.New(cfg.SSHTargets(), nil)
	k8sProxy := k8sproxy.New(cfg.K8sTargets(), host)
	awsProxy := awsproxy.New(cfg.AWSTargets(), host)

	sshListener, k8sListener, awsListener, err := listenAll(opts.sshListen, opts.k8sListen, opts.awsListen)
	if err != nil {
		return nil, err
	}
	// Everything from here on is undone on failure: the listeners close,
	// nothing sb issued stays behind a failed start.
	fail := func(err error) (*proxyServer, error) {
		sshListener.Close()
		k8sListener.Close()
		awsListener.Close()
		return nil, err
	}
	if err := sshProxy.WriteConfig(host, listenerPort(sshListener), dir); err != nil {
		return fail(err)
	}

	server := &proxyServer{ctx: ctx, errc: make(chan error, 6), ssh: sshProxy, k8s: k8sProxy, aws: awsProxy}
	// k8s and AWS signal the initial issuance's own result: nil is a
	// success, anything else fails the start.
	k8sReady, awsReady := make(chan error, 1), make(chan error, 1)
	go func() { server.errc <- k8sProxy.SyncConfig(ctx, listenerPort(k8sListener), dir, k8sReady) }()
	go func() { server.errc <- awsProxy.SyncConfig(ctx, listenerPort(awsListener), dir, awsReady) }()
	for _, ready := range []chan error{k8sReady, awsReady} {
		select {
		case err := <-ready:
			if err != nil {
				return fail(err)
			}
		case err := <-server.errc:
			return fail(err)
		}
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

// Stop stops the proxies: first they stop accepting and cancel their
// upstreams (the beginning of the shutdown, every proxy at once), then
// each waits for its cleanup within ctx's deadline. The deadline is made
// here, when the shutdown starts, so a long-lived session does not stop
// with an expired one.
func (s *proxyServer) Stop(ctx context.Context) {
	s.ssh.BeginStop()
	s.k8s.BeginStop()
	s.aws.BeginStop()
	s.ssh.Shutdown(ctx)
	s.k8s.Shutdown(ctx)
	s.aws.Shutdown(ctx)
}

func listenAll(sshAddr, k8sAddr, awsAddr string) (ssh, k8s, aws net.Listener, err error) {
	ssh, err = net.Listen("tcp", sshAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen ssh: %w", err)
	}
	k8s, err = net.Listen("tcp", k8sAddr)
	if err != nil {
		ssh.Close()
		return nil, nil, nil, fmt.Errorf("listen k8s: %w", err)
	}
	aws, err = net.Listen("tcp", awsAddr)
	if err != nil {
		ssh.Close()
		k8s.Close()
		return nil, nil, nil, fmt.Errorf("listen aws: %w", err)
	}
	return ssh, k8s, aws, nil
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
