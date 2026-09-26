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
	"time"

	"github.com/hrntknr/sb/internal/awsproxy"
	v3 "github.com/hrntknr/sb/internal/config/v3"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/session"
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
				// startProxy stops the issuances, waits for their
				// exit, and removes what they issued — or joins the
				// failed reclamation to the error, so what remains
				// behind is shown with it.
				return err
			}
			err = proxy.Wait()
			// The stop flow is the same on every exit: the proxies stop
			// accepting, cancel their upstreams, and are waited for
			// within the deadline. What did not exit keeps what it
			// issued: the removal would race what it is still
			// writing.
			if proxy.Stop(shutdownCtx()) {
				removeIssued(args[0])
			} else {
				err = errors.Join(err, fmt.Errorf("proxy stop: an issuing task did not exit within %s; remove %s by hand once it is done", session.RuntimeWait, args[0]))
			}
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
	// Everything after this point is undone on failure: the listeners
	// close, and what sb issued is removed with the issuances' exit —
	// or stays behind the failure, reported by its error, when they
	// did not exit.
	fail := func(err error) error {
		sshListener.Close()
		k8sListener.Close()
		awsListener.Close()
		return err
	}
	if err := sshProxy.WriteConfig(host, listenerPort(sshListener), dir); err != nil {
		// The ssh issuance failed midway: nothing sb issued stays
		// behind a failed start. Nothing else was started: the ssh
		// issuance runs before the issuing tasks.
		removeIssued(dir)
		return nil, fail(err)
	}

	server := &proxyServer{
		ctx: ctx, errc: make(chan error, 6),
		ssh: sshProxy, k8s: k8sProxy, aws: awsProxy,
	}
	// The issuing tasks' termination notifications are the server's:
	// the start's failure path and the normal stop both wait for them.
	k8sDone, awsDone := make(chan struct{}), make(chan struct{})
	server.k8sDone, server.awsDone = k8sDone, awsDone
	// The k8s and AWS issuances signal the initial write's own result
	// (nil: the initial issuance succeeded) through their ready channel —
	// the watcher setup's failure included; the goroutine's return (a
	// component's exit before its issuance was ready) is not that result.
	// The ports are taken here, before the goroutines start: a failure
	// path closes the listeners, and a closed listener's address is gone.
	k8sPort, awsPort := listenerPort(k8sListener), listenerPort(awsListener)
	k8sReady, awsReady := make(chan error, 1), make(chan error, 1)
	go func() {
		server.errc <- k8sProxy.SyncConfig(ctx, k8sPort, dir, k8sReady)
		close(k8sDone)
	}()
	go func() {
		server.errc <- awsProxy.SyncConfig(ctx, awsPort, dir, awsReady)
		close(awsDone)
	}()
	// A failure anywhere stops both issuances and waits for their exit:
	// the removal happens after what the other side issued landed, not
	// before it. What does not exit within the deadline is not waited
	// for; what it is still writing stays.
	failStartup := func(err error) (*proxyServer, error) {
		k8sProxy.BeginStop()
		awsProxy.BeginStop()
		if awaitDone(session.RuntimeWait, k8sDone, awsDone) {
			removeIssued(dir)
			return server, fail(err)
		}
		// What the tasks are still writing stays: the removal would race
		// it. The failed reclamation joins the startup error, so the
		// caller sees what remains behind and how to reclaim it.
		return server, fail(errors.Join(err, fmt.Errorf(
			"proxy start: an issuing task did not exit within %s; remove %s by hand once it is done", session.RuntimeWait, dir)))
	}
	for _, ready := range []chan error{k8sReady, awsReady} {
		// A cancelled run is a failed start, whatever the issuances
		// delivered: the check comes first, so a cancellation that
		// already happened is always the run's own result.
		if err := ctx.Err(); err != nil {
			return failStartup(err)
		}
		select {
		case err := <-ready:
			if err != nil {
				// The issuance that failed is not the only one
				// running: both stop here, and what they issued
				// is gone once they have exited.
				return failStartup(err)
			}
		case <-ctx.Done():
			// The run was cancelled mid-startup: not a success.
			// The components exit (their loops are cut by the
			// ctx), what they issued is gone, nothing starts.
			return failStartup(ctx.Err())
		}
	}
	// The last ready is in: a cancellation that began while it landed
	// is still a failed start.
	if err := ctx.Err(); err != nil {
		return failStartup(err)
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
	// k8sDone and awsDone close when the issuing tasks exit: the sync
	// goroutines' work is over. They are waited for within the shutdown
	// deadline, so the removal of what they issued happens after they
	// exit — not while they are still writing it.
	k8sDone chan struct{}
	awsDone chan struct{}
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
// each waits for its cleanup within ctx's deadline. The issuing tasks
// are waited for the same way: a write in flight at the stop completes
// before it returns. Stop reports whether they exited within ctx's
// deadline: false means the removal of what they issued must not happen
// — it would race what they are still writing.
func (s *proxyServer) Stop(ctx context.Context) bool {
	s.ssh.BeginStop()
	s.k8s.BeginStop()
	s.aws.BeginStop()
	exited := s.awaitIssuance(ctx)
	s.ssh.Shutdown(ctx)
	s.k8s.Shutdown(ctx)
	s.aws.Shutdown(ctx)
	return exited
}

// awaitIssuance waits for the issuing tasks' exit within ctx's deadline.
// What does not exit by then is given up on: what it is still writing
// may land after any removal, so the caller treats it as not reclaimed.
func (s *proxyServer) awaitIssuance(ctx context.Context) bool {
	for _, done := range []chan struct{}{s.k8sDone, s.awsDone} {
		select {
		case <-done:
		case <-ctx.Done():
			return false
		}
	}
	return true
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

// awaitDone waits for the issuing tasks' termination notifications within
// limit. What does not exit by then is given up on: what it is still
// writing may land after any removal, so the caller treats it as not
// reclaimed.
func awaitDone(limit time.Duration, done ...chan struct{}) bool {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	for _, ch := range done {
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
	}
	return true
}
