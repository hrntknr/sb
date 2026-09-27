package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"

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
	// may overwrite it. Its failure must show whatever the log level
	// (the default drops log lines): stderr carries it.
	if err := session.Sweep(sessionsDir); err != nil {
		fmt.Fprintf(os.Stderr, "sb: session sweep failed; orphans stay for the next sweep: %v\n", err)
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
	// The session's record persists what the next sweep needs: the
	// runtime and session ID to find the containers by label, the issue
	// dir to reissue, and the creation's state — the creation not
	// settled, the runtime may still commit the container — so a
	// sweep that finds it orphaned may not settle it on an empty
	// listing.
	rec := session.Record{
		Name: name, ID: sessionID, Runtime: rt.String(), IssueDir: issueDir,
		CreationSettled: false,
	}
	if err := session.SaveRecord(sessionsDir, rec); err != nil {
		os.RemoveAll(issueDir)
		lock.Release()
		return err
	}

	// Everything after this point runs the same stop flow, in order:
	//
	//   (1) the proxies stop accepting and cancel their upstreams,
	//       waiting for their cleanups within the deadline — whatever
	//       the CLIs are doing meanwhile;
	//   (2) the session stops: its containers are removed by label, its
	//       issue dir and record dropped — what could not be removed,
	//       or what is still being created (its result unknown), keeps
	//       the record for the next sweep;
	//   (3) the CLIs are killed and reaped within WaitDelay.
	//
	// Nothing in the flow waits for a CLI's own exit.
	var (
		proxy      *proxyServer
		create     *exec.Cmd
		start      *exec.Cmd
		createDone <-chan struct{}
		startDone  <-chan struct{}
		// creationUnknown tracks whether the container creation's
		// result is still unknown — the runtime may still commit the
		// container. It is set when the create CLI starts: the runtime
		// daemon may commit even after a non-zero exit (a connection
		// dropped after the daemon committed leaves the CLI's own
		// result unknown), and it is not cleared before the CLI
		// settles: the container exists as the session's ContainerID,
		// or nothing more will be committed for it. A stop before the
		// CLI starts keeps the result known — nothing was asked of
		// the runtime, nothing will be created — and may drop the
		// session's record and issue dir outright.
		creationUnknown bool
	)
	defer func() {
		var errs []error
		if retErr != nil {
			errs = append(errs, retErr)
		}
		// (1) Communication cut: the proxies stop accepting, cancel their
		// upstreams, and are waited for within the deadline — whatever
		// the CLIs are doing meanwhile.
		issuanceExited := true
		if proxy != nil {
			// The stop joins the issuing tasks within the deadline:
			// what did not exit is still writing — its issue dir and
			// the record stay, and the next sweep retries with them.
			issuanceExited = proxy.Stop(shutdownCtx())
		}
		// (2) Container reclaim: the session's containers are removed
		// by label, its issue dir and record dropped. What could not
		// be removed — or what is still being created, its result
		// unknown — keeps the record for the next sweep.
		if err := session.StopSession(sessionsDir, name, lock, issuanceExited, !creationUnknown); err != nil {
			errs = append(errs, err)
		}
		// (3) CLI collection: what is left of them is killed, and the
		// reaping is bounded by WaitDelay. Nothing in this flow waits
		// for a CLI's own exit.
		if createDone != nil {
			_ = create.Process.Kill()
			<-createDone
		}
		if startDone != nil {
			_ = start.Process.Kill()
			<-startDone
		}
		if len(errs) > 0 {
			retErr = errors.Join(errs...)
		}
	}()

	slog.Info("running container", "runtime", rt.String(), "host", host, "session", name, "dir", issueDir)

	runCtx := cmd.Context()
	runCtx, stop := signal.NotifyContext(runCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The run's own proxies listen on every interface: the container
	// reaches the host across a network boundary, so a loopback-only
	// listen would keep them out of the container's reach.
	proxy, err = startProxy(runCtx, cfg, runListenAddr, runListenAddr, runListenAddr, host, issueDir)
	if err != nil {
		return err
	}
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Wait() }()

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))

	// The creation is its own step: the CLI creates the container stopped,
	// writes its ID to the cidfile under the issue dir, and exits. Nothing
	// runs before the container's ID is fixed — the reclaim may not settle
	// what the runtime has not committed yet.
	create = exec.CommandContext(runCtx, rt.Binary(), containers.CreateArgs(
		rt, host, issueDir, enabledProtocols(cfg), name, network,
		envArgs(cfg.Container.Environment), tty,
		mountArgs(cfg.Container.Mounts),
		[]string{containers.SessionLabelArg(sessionID)},
		image, init, userArgs,
	)...)
	// The ID the CLI prints on stdout is noise here; its stderr is the
	// creation's own complaint.
	create.Stdout = io.Discard
	create.Stderr = os.Stderr
	create.WaitDelay = session.RuntimeWait
	if err := create.Start(); err != nil {
		return err
	}
	// The creation is in flight: the CLI is running, the runtime
	// daemon may commit the container. From here the stop flow may
	// not drop the session's record on what it cannot confirm.
	creationUnknown = true
	createDone2 := make(chan struct{})
	createDone = createDone2
	createErr := make(chan error, 1)
	go func() {
		err := create.Wait()
		close(createDone2)
		createErr <- err
	}()

	// Wait for whatever ends this step. A CLI's exit is never the
	// condition for stopping: whatever ends it here, the same stop flow
	// follows on return.
	select {
	case err := <-proxyErr:
		if err != nil {
			// A proxy component failed: the CLIs are killed and reaped
			// by the deferred stop flow.
			retErr = fmt.Errorf("proxy: %w", err)
			return retErr
		}
		// Interrupted: the creation CLI was killed by the signal
		// already; its result is unknown.
		retErr = nil
		return retErr
	case err := <-createErr:
		if err != nil && runCtx.Err() == nil {
			// The creation failed on its own: the CLI's own
			// complaint. What the runtime daemon did with it is
			// unknown — a connection dropped after the daemon
			// committed leaves the CLI's exit non-zero and the
			// container created — so its result stays unknown,
			// and the stop flow keeps the record.
			retErr = fmt.Errorf("create: %w", err)
			return retErr
		}
		if err != nil {
			// Interrupted: the creation CLI was killed
			// mid-creation; its result is unknown. Nothing starts.
			retErr = nil
			return retErr
		}
		// The creation settled: the container exists, stopped. Record
		// its ID in the session record — sb exec verifies against it —
		// then start it: nothing starts before the ID is fixed.
		rec.ContainerID = containerID(issueDir)
		if rec.ContainerID == "" {
			// The runtime exited without recording an ID: nothing
			// may start, and the record stays for the next sweep.
			retErr = errors.New("runtime exited without recording the container ID")
			return retErr
		}
		creationUnknown = false
		// The settled result persists with the ID: a sweep that finds
		// this record may reclaim it, but not before.
		rec.CreationSettled = true
		if err := session.SaveRecord(sessionsDir, rec); err != nil {
			retErr = fmt.Errorf("session record: %w", err)
			return retErr
		}
	}

	// The execution is its own step: the CLI starts the created
	// container and attaches to it — its streams are the container's,
	// its exit is the container's.
	start = exec.CommandContext(runCtx, rt.Binary(), containers.StartArgs(rec.ContainerID, tty)...)
	start.Stdin, start.Stdout, start.Stderr = os.Stdin, os.Stdout, os.Stderr
	start.WaitDelay = session.RuntimeWait
	if err := start.Start(); err != nil {
		return err
	}
	startDone2 := make(chan struct{})
	startDone = startDone2
	startErr := make(chan error, 1)
	go func() {
		err := start.Wait()
		close(startDone2)
		startErr <- err
	}()

	// Wait for whatever ends the run: a proxy component failing, the
	// interruption, or the start CLI — whose exit is the container's —
	// exiting by itself.
	select {
	case err := <-proxyErr:
		if err != nil {
			retErr = fmt.Errorf("proxy: %w", err)
			return retErr
		}
		// Interrupted: the CLIs were killed by the signal already.
		retErr = nil
		return retErr
	case err := <-startErr:
		// The start CLI exited by itself: its exit is the run's.
		retErr = exitStatus(err)
		return retErr
	}
}

// containerID reads the ID the creation CLI recorded in the cidfile under
// the issue dir: the container's ID, fixed once the CLI exited. An empty
// answer means the runtime recorded nothing.
func containerID(issueDir string) string {
	data, err := os.ReadFile(containers.CidFile(issueDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
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
