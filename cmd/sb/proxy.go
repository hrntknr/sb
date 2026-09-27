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
	"strings"
	"syscall"
	"time"

	"github.com/hrntknr/sb/internal/awsproxy"
	v3 "github.com/hrntknr/sb/internal/config/v3"
	"github.com/hrntknr/sb/internal/containers"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/session"
	"github.com/hrntknr/sb/internal/sshproxy"
	"github.com/spf13/cobra"
)

// newProxyCommand builds `sb proxy --output dir`: the credential proxy
// without any container management, for manual downstreams.
func newProxyCommand(opts *options) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:           "proxy --output dir",
		Short:         "Run the credential proxy, writing .ssh, .kube and .aws under the --output directory",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := configureLogger(opts.logLevel); err != nil {
				return err
			}
			if err := requireEmptyDir(dir); err != nil {
				return err
			}
			cfg, err := v3.Load(opts.configPath)
			if err != nil {
				return err
			}
			if err := checkProxyExposure(cmd, *opts); err != nil {
				return err
			}
			slog.Info("starting sb proxy", "config", opts.configPath, "host", opts.host, "ssh_listen", opts.sshListen, "k8s_listen", opts.k8sListen, "aws_listen", opts.awsListen, "dir", dir)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			proxy, err := startProxy(ctx, cfg, *opts, opts.host, dir)
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
				// The issuing tasks exited: what they issued is gone.
				// What could not be removed joins the result: it stays
				// behind the exit, and the user must see it — a log
				// line would vanish under the default level.
				if rerr := removeIssued(dir); rerr != nil {
					err = errors.Join(err, rerr)
				}
			} else {
				err = errors.Join(err, fmt.Errorf("proxy stop: an issuing task did not exit within %s; remove %s by hand once it is done", session.RuntimeWait, dir))
			}
			return err
		},
	}
	cmd.Flags().StringVar(&dir, "output", "", "directory to write the issued credentials under")
	_ = cmd.MarkFlagRequired("output")
	cmd.Flags().StringVar(&opts.host, "host", "localhost", "host written into the generated credentials (also covered by the k8s proxy certificate); required when a --*-listen binds beyond loopback")
	cmd.Flags().StringVar(&opts.sshListen, "ssh-listen", defaultListenAddr, "ssh listen address")
	cmd.Flags().StringVar(&opts.k8sListen, "k8s-listen", defaultListenAddr, "k8s listen address")
	cmd.Flags().StringVar(&opts.awsListen, "aws-listen", defaultListenAddr, "aws listen address")
	return cmd
}

// checkProxyExposure verifies the proxy's exposure before it starts.
// Listening beyond loopback must be a decision: the credentials point
// downstreams at the host they reach the proxy at, so it must be given.
// That host must be a destination: a wildcard address (0.0.0.0, ::)
// listens, nothing connects to it.
func checkProxyExposure(cmd *cobra.Command, opts options) error {
	switch strings.TrimSpace(strings.Trim(opts.host, "[]")) {
	case "", "0.0.0.0", "::":
		return fmt.Errorf("--host %q: a wildcard address is not a destination; give the host downstreams reach the proxy at", opts.host)
	}
	if !cmd.Flags().Changed("host") && !loopbackListens(opts.sshListen, opts.k8sListen, opts.awsListen) {
		return fmt.Errorf("listening beyond loopback requires --host: the generated credentials point downstreams at the host they reach the proxy at; give it")
	}
	return nil
}

// loopbackListens reports whether every listen address binds only the
// loopback interface: the proxy is not reached from beyond the host then.
// Anything else — a wildcard (":port", "0.0.0.0:port", "[::]:port"), another
// address, or a name — binds or resolves beyond it.
func loopbackListens(addrs ...string) bool {
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return false
		}
		switch strings.Trim(host, "[]") {
		case "", "0.0.0.0", "::":
			return false // binds every interface
		case "127.0.0.1", "localhost", "::1":
			continue // binds loopback only
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			continue // a loopback address (e.g. 127.0.0.2)
		}
		return false // another address, or a name: binds beyond loopback
	}
	return true
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
// .kube, and .aws subtrees. Anything else in dir is not sb's to delete. It
// reports what could not be removed: the caller joins that into the
// result, so the failure shows whatever the log level.
func removeIssued(dir string) error {
	var errs []error
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", filepath.Join(dir, name), err))
		}
	}
	return errors.Join(errs...)
}

// enabledProtocols returns the protocols the configuration has rules for:
// the ones a proxy is started for, the credentials are issued for, and
// the container mounts the credentials for. A protocol without rules is
// not started at all: it has nothing to serve, so nothing is issued
// under its name and its sources are not read either.
func enabledProtocols(cfg v3.Config) containers.Protocol {
	var protocols containers.Protocol
	if len(cfg.SSH) > 0 {
		protocols |= containers.ProtocolSSH
	}
	if len(cfg.K8s) > 0 {
		protocols |= containers.ProtocolK8s
	}
	if len(cfg.AWS) > 0 {
		protocols |= containers.ProtocolAWS
	}
	return protocols
}

// startProxy starts the proxies serving the protocols the configuration
// has rules for, and returns once every issuance is on disk: the ssh
// config and keys (written synchronously), the k8s and AWS credentials
// (their ready channel carries the initial write's own result — nil is a
// success). A protocol without rules is not started at all: it is not
// served, nothing is issued under its name, and its sources are not
// read. Every failure path closes the listeners. host is the address
// downstreams use to reach the proxy. Cancel ctx to stop them.
func startProxy(ctx context.Context, cfg v3.Config, opts options, host, dir string) (*proxyServer, error) {
	sshProxy := sshproxy.New(cfg.SSHTargets(), nil)
	k8sProxy := k8sproxy.New(cfg.K8sTargets(), host)
	awsProxy := awsproxy.New(cfg.AWSTargets(), host)

	// The listeners of the protocols in use: a protocol without rules
	// gets no listener — what is not started gets no port either.
	sshListener, k8sListener, awsListener, err := listenAll(opts.sshListen, opts.k8sListen, opts.awsListen, enabledProtocols(cfg))
	if err != nil {
		return nil, err
	}
	// Everything after this point is undone on failure: the listeners
	// close, and what sb issued is removed with the issuances' exit —
	// or stays behind the failure, reported by its error, when they
	// did not exit.
	fail := func(err error) error {
		closeListeners(sshListener, k8sListener, awsListener)
		return err
	}
	if sshListener != nil {
		if err := sshProxy.WriteConfig(host, listenerPort(sshListener), dir); err != nil {
			// The ssh issuance failed midway: nothing sb issued stays
			// behind a failed start. Nothing else was started: the ssh
			// issuance runs before the issuing tasks. What could not be
			// removed joins the failure: it stays behind it, and the
			// caller must see it.
			if rerr := removeIssued(dir); rerr != nil {
				return nil, fail(errors.Join(err, rerr))
			}
			return nil, fail(err)
		}
	}

	server := &proxyServer{ctx: ctx, errc: make(chan error, 6)}
	// The issuing tasks' termination notifications are the server's:
	// the start's failure path and the normal stop both wait for them.
	// The k8s and AWS issuances signal the initial write's own result
	// (nil: the initial issuance succeeded) through their ready channel —
	// the setup's own failure included; the goroutine's return (a
	// component's exit before its issuance was ready) is not that result.
	// The ports are taken inside the blocks, before the goroutines start:
	// a failure path closes the listeners, and a closed listener's
	// address is gone.
	var readies []chan error
	if sshListener != nil {
		server.started = append(server.started, sshProxy)
	}
	if k8sListener != nil {
		k8sDone := make(chan struct{})
		server.started = append(server.started, k8sProxy)
		server.issuing = append(server.issuing, k8sDone)
		k8sReady := make(chan error, 1)
		readies = append(readies, k8sReady)
		go func() {
			server.errc <- k8sProxy.SyncConfig(ctx, listenerPort(k8sListener), dir, k8sReady)
			close(k8sDone)
		}()
	}
	if awsListener != nil {
		awsDone := make(chan struct{})
		server.started = append(server.started, awsProxy)
		server.issuing = append(server.issuing, awsDone)
		awsReady := make(chan error, 1)
		readies = append(readies, awsReady)
		go func() {
			server.errc <- awsProxy.SyncConfig(ctx, listenerPort(awsListener), dir, awsReady)
			close(awsDone)
		}()
	}
	// A failure anywhere stops every started protocol and waits for the
	// issuing tasks' exit: the removal happens after what the other
	// side issued landed, not before it. What does not exit within the
	// deadline is not waited for; what it is still writing stays.
	failStartup := func(err error) (*proxyServer, error) {
		for _, p := range server.started {
			p.BeginStop()
		}
		if awaitDone(session.RuntimeWait, server.issuing...) {
			// The issuing tasks exited: what they issued is gone, or
			// its removal failed — which stays behind the failure,
			// joined so the caller sees it.
			if rerr := removeIssued(dir); rerr != nil {
				return server, fail(errors.Join(err, rerr))
			}
			return server, fail(err)
		}
		// What the tasks are still writing stays: the removal would race
		// it. The failed reclamation joins the startup error, so the
		// caller sees what remains behind and how to reclaim it.
		return server, fail(errors.Join(err, fmt.Errorf(
			"proxy start: an issuing task did not exit within %s; remove %s by hand once it is done", session.RuntimeWait, dir)))
	}
	for _, ready := range readies {
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

	if sshListener != nil {
		go serve(ctx, server.errc, sshListener, sshProxy.Serve)
	}
	if k8sListener != nil {
		go serve(ctx, server.errc, k8sListener, k8sProxy.Serve)
	}
	if awsListener != nil {
		go serve(ctx, server.errc, awsListener, awsProxy.Serve)
	}
	return server, nil
}

// proxyComponent is the shutdown surface of a started proxy component:
// the beginning of the shutdown, and the wait for its cleanup.
type proxyComponent interface {
	BeginStop()
	Shutdown(ctx context.Context)
}

// proxyServer runs the started proxy components on background goroutines
// until ctx is cancelled or one of them fails.
type proxyServer struct {
	ctx  context.Context
	errc chan error
	// started holds the started components: the stop stops exactly
	// these — one per protocol in use, in the order they started.
	started []proxyComponent
	// issuing holds the started issuing tasks' exit notifications:
	// the sync goroutines' work is over. They are waited for within the
	// shutdown deadline, so the removal of what they issued happens
	// after they exit — not while they are still writing it.
	issuing []chan struct{}
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

// Stop stops the started components: first they stop accepting and cancel
// their upstreams (the beginning of the shutdown, every started one at
// once), then each waits for its cleanup within ctx's deadline. The
// started issuing tasks are waited for the same way: a write in flight
// at the stop completes before it returns. Stop reports whether they
// exited within ctx's deadline: false means the removal of what they
// issued must not happen — it would race what they are still writing.
func (s *proxyServer) Stop(ctx context.Context) bool {
	for _, p := range s.started {
		p.BeginStop()
	}
	exited := s.awaitIssuance(ctx)
	for _, p := range s.started {
		p.Shutdown(ctx)
	}
	return exited
}

// awaitIssuance waits for the started issuing tasks' exit within ctx's
// deadline. What does not exit by then is given up on: what it is still
// writing may land after any removal, so the caller treats it as not
// reclaimed.
func (s *proxyServer) awaitIssuance(ctx context.Context) bool {
	for _, done := range s.issuing {
		select {
		case <-done:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// listenAll opens one listener per protocol in use: a protocol without
// rules gets none — what is not started gets no port either.
func listenAll(sshAddr, k8sAddr, awsAddr string, protocols containers.Protocol) (ssh, k8s, aws net.Listener, err error) {
	if protocols&containers.ProtocolSSH != 0 {
		ssh, err = net.Listen("tcp", sshAddr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("listen ssh: %w", err)
		}
	}
	if protocols&containers.ProtocolK8s != 0 {
		k8s, err = net.Listen("tcp", k8sAddr)
		if err != nil {
			closeListeners(ssh)
			return nil, nil, nil, fmt.Errorf("listen k8s: %w", err)
		}
	}
	if protocols&containers.ProtocolAWS != 0 {
		aws, err = net.Listen("tcp", awsAddr)
		if err != nil {
			closeListeners(ssh, k8s)
			return nil, nil, nil, fmt.Errorf("listen aws: %w", err)
		}
	}
	return ssh, k8s, aws, nil
}

// closeListeners closes the listeners that were opened: a protocol that
// got none stays closed. Closing a nil listener would panic, and the
// disabled protocols have none.
func closeListeners(listeners ...net.Listener) {
	for _, l := range listeners {
		if l != nil {
			l.Close()
		}
	}
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
