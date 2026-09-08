package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/hrntknr/secretbridge/internal/containers"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newRunCommand(opts *options) *cobra.Command {
	var runtimeFlag string
	cmd := &cobra.Command{
		Use:   "run [--] <args>...",
		Short: "Run a container with secretbridge credentials",
		Long: `Run a container with scoped ssh and k8s credentials mounted in.

The runtime (docker, podman, or the apple container CLI) is detected
automatically; select one with --runtime. All arguments are passed to the
runtime's run command unchanged; prefix them with -- when they start with -:

  secretbridge run alpine sh
  secretbridge run -- -v $PWD:/work -it node npm install`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainer(cmd.Context(), *opts, runtimeFlag, args)
		},
	}
	cmd.Flags().StringVar(&runtimeFlag, "runtime", "auto", "container runtime: auto, docker, podman, or apple")
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return fmt.Errorf("%w\nruntime options must come after --, e.g. secretbridge run -- -v $PWD:/work alpine", err)
	})
	return cmd
}

func runContainer(ctx context.Context, opts options, runtimeFlag string, userArgs []string) error {
	if containers.HasDetach(userArgs) {
		return errors.New("run: -d/--detach is not supported; the proxy must outlive the container")
	}
	if err := configureLogger(opts.logLevel); err != nil {
		return err
	}
	rt, err := resolveRuntime(runtimeFlag)
	if err != nil {
		return err
	}
	opts.host = rt.Host()
	if rt != containers.Apple && containers.UsesHostNetwork(userArgs) {
		opts.host = "localhost"
	} else if err := rt.Check(); err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "secretbridge-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	slog.Info("running container", "runtime", rt.String(), "host", opts.host, "dir", dir)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	proxy, err := startProxy(ctx, opts, dir)
	if err != nil {
		return err
	}
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Wait() }()

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.Args(rt, dir, tty, userArgs)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		stop()
		return err
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- child.Wait() }()

	select {
	case err := <-proxyErr:
		if err != nil {
			_ = child.Process.Kill()
			<-waitErr
			return fmt.Errorf("proxy: %w", err)
		}
		// Interrupted: the child got the signal too; wait for it to exit.
		return exitStatus(<-waitErr)
	case err := <-waitErr:
		stop()
		return exitStatus(err)
	}
}

func resolveRuntime(flag string) (containers.Runtime, error) {
	if flag == "" || flag == "auto" {
		return containers.Detect()
	}
	return containers.Parse(flag)
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

// exitCodeError makes the secretbridge process exit with the container's
// exit code instead of a generic error.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }
