package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	v3 "github.com/hrntknr/sb/internal/config/v3"
	"github.com/hrntknr/sb/internal/containers"
	"github.com/hrntknr/sb/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newRunCommand(opts *options) *cobra.Command {
	var name, network string
	var init bool
	cmd := &cobra.Command{
		Use:   "run [--] <command>...",
		Short: "Run a container with sb credentials",
		Long: `Run a container with scoped ssh, k8s and AWS credentials mounted in.

The image comes from container.image in the config (required); the
runtime (docker, podman, or the apple container CLI) is detected
automatically or selected with container.runtime. Mounts configured
under container.mounts are passed as -v options.

The arguments form the container command; no arguments runs the
image's default command. Use -- when the command starts with -.

--name names the session: the same name identifies it to sb exec, and
starting a second live session with that name is refused. Omitting
--name generates a fresh one, printed on stderr, so a second run never
collides with the first. Examples:

  sb run
  sb run zsh -l
  sb run --name dev -- zsh -l

--network selects the container's network:

  sb run --network host zsh -l

--init runs the command under an init process as PID 1 that
forwards signals and reaps zombie processes:

  sb run --init zsh -l`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainer(cmd, *opts, name, network, init, args)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name for the session, targeted by sb exec; omitted generates one")
	cmd.Flags().StringVar(&network, "network", "", "network for the container (with host, the proxy is reached as localhost)")
	cmd.Flags().BoolVar(&init, "init", false, "run an init process as PID 1 that forwards signals and reaps zombies")
	// Flags after the first plain argument belong to the container
	// command, not to sb.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runContainer(cmd *cobra.Command, opts options, name, network string, init bool, userArgs []string) (retErr error) {
	if err := configureLogger(opts.logLevel); err != nil {
		return err
	}

	cfg, err := v3.Load(opts.configPath)
	if err != nil {
		return err
	}
	if err := checkMountSources(cfg.Container.Mounts); err != nil {
		return err
	}
	image := cfg.Container.Image
	if image == "" {
		return errors.New("run: container.image is required in the config")
	}

	rt, err := resolveRuntime(cfg.Container.Runtime)
	if err != nil {
		return err
	}
	host, err := containers.ResolveHost(rt, network)
	if err != nil {
		return err
	}

	sessionsDir, err := session.SessionsDir()
	if err != nil {
		return err
	}
	// Orphans from a killed sb are reclaimed here: their locks are gone,
	// so the sweep stops and removes their containers by session label.
	// What the sweep could not remove stays for the next sweep — nothing
	// may overwrite it.
	if err := session.Sweep(sessionsDir); err != nil {
		slog.Warn("session sweep failed; orphans stay for the next sweep", "error", err)
	}
	if name == "" {
		name = session.NewSessionName()
	}
	// The name goes to stderr whatever the log level: it is what sb exec
	// needs, not a log line.
	fmt.Fprintf(os.Stderr, "sb: session %q (exec: sb exec --name %q)\n", name, name)
	lock, err := session.Acquire(sessionsDir, name)
	if err != nil {
		return err
	}

	sessionID := session.NewSessionID()
	issueDir, err := session.NewIssueDir(sessionID)
	if err != nil {
		lock.Release()
		return err
	}
	rec := session.Record{Name: name, ID: sessionID, Runtime: rt.String(), IssueDir: issueDir}
	if err := session.SaveRecord(sessionsDir, rec); err != nil {
		os.RemoveAll(issueDir)
		lock.Release()
		return err
	}

	// Everything after this point runs the same stop flow, in order:
	//
	//   (1) the proxies stop accepting and cancel their upstreams,
	//       waiting for their cleanups within the deadline — whatever
	//       the child CLI is doing meanwhile;
	//   (2) the poller stops, then the session stops: its containers are
	//       removed by label, its issue dir and record dropped — what
	//       could not be removed keeps the record for the next sweep;
	//   (3) the child CLI is killed and reaped within WaitDelay.
	//
	// Nothing in the flow waits for the child's own exit.
	var (
		proxy     *proxyServer
		child     *exec.Cmd
		pollStop  chan struct{}
		pollDone  <-chan struct{}
		childDone <-chan struct{}
	)
	defer func() {
		var errs []error
		if retErr != nil {
			errs = append(errs, retErr)
		}
		// (1) Communication cut: the proxies stop accepting, cancel their
		// upstreams, and are waited for within the deadline — whatever
		// the child CLI is doing meanwhile.
		if proxy != nil {
			proxy.Stop(shutdownCtx())
		}
		if pollDone != nil {
			// (2) The poller stops: nothing records the container ID
			// anymore, whatever the child CLI does next.
			close(pollStop)
			<-pollDone
		}
		// (3) Container reclaim: the session's containers are removed
		// by label, its issue dir and record dropped. What could not be
		// removed keeps the record for the next sweep.
		if err := session.StopSession(sessionsDir, name, lock); err != nil {
			errs = append(errs, err)
		}
		// (4) Child collection: what is left of the CLI is killed, and
		// its reaping is bounded by WaitDelay. Nothing in this flow
		// waits for the child's own exit.
		if childDone != nil {
			_ = child.Process.Kill()
			<-childDone
		}
		if len(errs) > 0 {
			retErr = errors.Join(errs...)
		}
	}()

	slog.Info("running container", "runtime", rt.String(), "host", host, "session", name, "dir", issueDir)

	runCtx := cmd.Context()
	runCtx, stop := signal.NotifyContext(runCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	proxy, err = startProxy(runCtx, cfg, opts, host, issueDir)
	if err != nil {
		return err
	}
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Wait() }()

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child = exec.CommandContext(runCtx, rt.Binary(), containers.Args(
		rt, host, issueDir, name, network,
		envArgs(cfg.Container.Environment), tty,
		mountArgs(cfg.Container.Mounts),
		[]string{containers.SessionLabelArg(sessionID)},
		image, init, userArgs,
	)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.WaitDelay = session.RuntimeWait
	if err := child.Start(); err != nil {
		return err
	}
	childDone2 := make(chan struct{})
	childDone = childDone2
	pollStop = make(chan struct{})

	// The runtime CLI writes the container ID to the cidfile under the
	// issue dir once the container exists; recording it is what sb exec
	// verifies against the runtime. The poller stops when the stop flow
	// starts (pollStop), not when the CLI exits — its recording is not
	// part of the child's collection.
	childErr := make(chan error, 1)
	go func() {
		err := child.Wait()
		close(childDone2)
		childErr <- err
	}()
	pollDone2 := make(chan struct{})
	pollDone = pollDone2
	go func() {
		defer close(pollDone2)
		recordContainerID(sessionsDir, &rec, issueDir, pollStop)
	}()

	// Wait for whatever ends the run. The child's exit is never the
	// condition for stopping: whatever ends it here, the same stop flow
	// follows on return.
	select {
	case err := <-proxyErr:
		if err != nil {
			// A proxy component failed: the child is killed and reaped
			// by the deferred stop flow.
			retErr = fmt.Errorf("proxy: %w", err)
			return retErr
		}
		// Interrupted: the child was killed by the signal already.
		retErr = nil
		return retErr
	case err := <-childErr:
		// The child exited by itself: its exit is the run's.
		retErr = exitStatus(err)
		return retErr
	}
}

// recordContainerID waits for the runtime CLI to write the container ID to
// the cidfile under the issue dir and records it in the session record for
// sb exec. It returns when stop is closed (the stop flow started) — with or
// without a cidfile.
func recordContainerID(sessionsDir string, rec *session.Record, issueDir string, stop <-chan struct{}) {
	cidPath := filepath.Join(issueDir, "cid")
	for {
		if data, err := os.ReadFile(cidPath); err == nil {
			if cid := strings.TrimSpace(string(data)); cid != "" && cid != rec.ContainerID {
				rec.ContainerID = cid
				if err := session.SaveRecord(sessionsDir, *rec); err != nil {
					slog.Warn("session record: save container ID", "error", err)
					return
				}
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func resolveRuntime(name string) (containers.Runtime, error) {
	if name == "" || name == "auto" {
		return containers.Detect()
	}
	return containers.Parse(name)
}

// checkMountSources fails early when a configured mount's source does not
// exist: the runtime would silently create it (owned by root) instead.
func checkMountSources(mounts []v3.Mount) error {
	for _, mount := range mounts {
		if _, err := os.Stat(mount.Source); err != nil {
			return fmt.Errorf("mount source %s: %w", mount.Source, err)
		}
	}
	return nil
}

// envArgs renders the config's environment map as runtime --env values:
// an inherited variable passes just its name, a fixed one KEY=VALUE.
func envArgs(envs map[string]v3.Env) []string {
	args := make([]string, 0, len(envs))
	for _, key := range slices.Sorted(maps.Keys(envs)) {
		if envs[key].Inherit {
			args = append(args, key)
		} else {
			args = append(args, key+"="+envs[key].Value)
		}
	}
	return args
}

// mountArgs renders the config's mounts as runtime -v values; a read-only
// mount carries the :ro option.
func mountArgs(mounts []v3.Mount) []string {
	args := make([]string, 0, len(mounts))
	for _, m := range mounts {
		v := m.Source + ":" + m.Target
		if m.ReadOnly {
			v += ":ro"
		}
		args = append(args, v)
	}
	return args
}

func exitStatus(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
		return &exitCodeError{exitErr.ExitCode()}
	}
	return fmt.Errorf("container: %w", err)
}

// exitCodeError makes the sb process exit with the container's
// exit code instead of a generic error.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// shutdownCtx bounds a proxy shutdown: a background context that fails at
// the shutdown deadline, so a step that would hang is cut there. The
// deadline is made when the shutdown starts, not when the run does.
func shutdownCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), session.RuntimeWait)
	// Shutdown returns by the deadline; cancel only holds the timer for
	// that long.
	_ = cancel
	return ctx
}
