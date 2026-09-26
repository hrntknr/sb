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

	"github.com/hrntknr/sb/internal/containers"
	v3 "github.com/hrntknr/sb/internal/config/v3"
	"github.com/hrntknr/sb/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// shutdownWait bounds each stop-flow step: how long the proxies' Shutdown
// waits for open connections (SSH transfers, k8s watches, logs -f) before
// cutting them.
const shutdownWait = 5 * time.Second

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
starting a second live session with that name is refused. Examples:

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
	cmd.Flags().StringVar(&name, "name", "default", "name for the session, targeted by sb exec")
	cmd.Flags().StringVar(&network, "network", "", "network for the container (with host, the proxy is reached as localhost)")
	cmd.Flags().BoolVar(&init, "init", false, "run an init process as PID 1 that forwards signals and reaps zombies")
	// Flags after the first plain argument belong to the container
	// command, not to sb.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runContainer(cmd *cobra.Command, opts options, name, network string, init bool, userArgs []string) error {
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
	if err := session.Sweep(sessionsDir); err != nil {
		slog.Warn("session sweep failed; orphans stay for the next sweep", "error", err)
	}
	lock, err := session.Acquire(sessionsDir, name)
	if err != nil {
		return err
	}
	sessionID := session.NewSessionID()
	issueDir, err := session.NewIssueDir(sessionID)
	if err != nil {
		return err
	}
	rec := session.Record{Name: name, ID: sessionID, Runtime: rt.String(), IssueDir: issueDir}
	if err := session.SaveRecord(sessionsDir, rec); err != nil {
		return err
	}
	// Every exit path — normal exit, interrupt, proxy failure, or startup
	// failure — runs the same session stop flow.
	defer stopSession(sessionsDir, &rec, lock, rt)

	slog.Info("running container", "runtime", rt.String(), "host", host, "session", name, "dir", issueDir)

	ctx := cmd.Context()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	proxy, err := startProxy(ctx, cfg, opts, host, issueDir)
	if err != nil {
		return err
	}
	defer proxy.Shutdown(shutdownCtx())
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Wait() }()

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.Args(
		rt, host, issueDir, name, network,
		envArgs(cfg.Container.Environment), tty,
		mountArgs(cfg.Container.Mounts),
		[]string{containers.SessionLabelArg(sessionID)},
		image, init, userArgs,
	)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		stop()
		return err
	}
	childDone := make(chan struct{})
	waitErr := make(chan error, 1)
	go func() {
		err := child.Wait()
		close(childDone) // broadcast: the poller and the run both watch it
		waitErr <- err
	}()

	// The runtime CLI writes the container ID to the cidfile under the
	// issue dir once the container exists; recording it is what sb exec
	// verifies against the runtime.
	cidDone := make(chan struct{})
	go func() {
		defer close(cidDone)
		recordContainerID(sessionsDir, &rec, issueDir, childDone)
	}()

	select {
	case err := <-proxyErr:
		if err != nil {
			_ = child.Process.Kill()
			<-waitErr
			<-cidDone
			return fmt.Errorf("proxy: %w", err)
		}
		// Interrupted: the child got the signal too; wait for it to exit.
		err = <-waitErr
		<-cidDone
		return exitStatus(err)
	case err := <-waitErr:
		stop()
		<-cidDone
		return exitStatus(err)
	}
}

// stopSession is the session's stop flow. It runs after the container (if
// one was started) exited: the session's containers are stopped and removed
// by session label, then the issue dir, record, and lock are dropped. It
// tolerates half-started sessions: a container that never started leaves
// nothing behind.
func stopSession(sessionsDir string, rec *session.Record, lock *session.Lock, rt containers.Runtime) {
	if err := containers.RemoveSession(rt, rec.ID); err != nil {
		slog.Warn("session stop: remove containers", "session", rec.Name, "id", rec.ID, "error", err)
	}
	if err := os.RemoveAll(rec.IssueDir); err != nil {
		slog.Warn("session stop: remove issue dir", "dir", rec.IssueDir, "error", err)
	}
	if err := lock.DeleteRecord(sessionsDir, rec.Name); err != nil {
		slog.Warn("session stop: delete record", "session", rec.Name, "error", err)
	}
}

// recordContainerID waits for the runtime CLI to write the container ID to
// the cidfile under the issue dir and records it in the session record for
// sb exec. It returns when the CLI exits (done closing) — with or without
// a cidfile.
func recordContainerID(sessionsDir string, rec *session.Record, issueDir string, done <-chan struct{}) {
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
		case <-done:
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
// the shutdown deadline, so a step that would hang is cut there.
func shutdownCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownWait)
	// Shutdown returns by the deadline; cancel only holds the timer for
	// that long.
	_ = cancel
	return ctx
}
