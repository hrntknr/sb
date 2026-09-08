package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hrntknr/sb/internal/config"
	"github.com/hrntknr/sb/internal/containers"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newRunCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [--] <args>...",
		Short: "Run a container with sb credentials",
		Long: `Run a container with scoped ssh and k8s credentials mounted in.

The runtime (docker, podman, or the apple container CLI) is detected
automatically; select one with container.runtime in the config. Mounts
configured under container.mounts are passed as -v options.

Without a container.image in the config, all arguments are passed to the
runtime's run command unchanged; prefix them with -- when they start with -:

  sb run alpine sh
  sb run -- -v $PWD:/work -it node npm install

With container.image configured, the arguments form the container command
and no arguments at all runs the image's default command; use -- when the
command itself starts with -:

  sb run claude
  sb run -- claude --settings '{"sandbox":{"enabled":false}}'`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainer(cmd, *opts, args)
		},
	}
	// Flags after the first plain argument belong to the container command,
	// not to sb.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runContainer(cmd *cobra.Command, opts options, userArgs []string) error {
	if containers.HasDetach(userArgs) {
		return errors.New("run: -d/--detach is not supported; the proxy must outlive the container")
	}
	if err := configureLogger(opts.logLevel); err != nil {
		return err
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	if err := checkMountSources(cfg.Container.Mounts); err != nil {
		return err
	}
	image := cfg.Container.Image
	if image == "" && len(userArgs) == 0 {
		return errors.New("run: an image is required; set container.image in the config or pass one as an argument")
	}

	rt, err := resolveRuntime(cfg.Container.Runtime)
	if err != nil {
		return err
	}
	host, err := containers.ResolveHost(rt, userArgs)
	if err != nil {
		return err
	}
	opts.host = host

	dir, err := os.MkdirTemp("", "sb-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	slog.Info("running container", "runtime", rt.String(), "host", opts.host, "dir", dir)

	ctx := cmd.Context()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	proxy, err := startProxy(ctx, opts, dir)
	if err != nil {
		return err
	}
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Wait() }()

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.Args(rt, host, dir, tty, cfg.Container.Mounts, image, userArgs)...)
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

func resolveRuntime(name string) (containers.Runtime, error) {
	if name == "" || name == "auto" {
		return containers.Detect()
	}
	return containers.Parse(name)
}

// checkMountSources fails early when a configured mount's source does not
// exist: the runtime would silently create it (owned by root) instead.
func checkMountSources(mounts []string) error {
	for _, mount := range mounts {
		source, _, _ := strings.Cut(mount, ":")
		if _, err := os.Stat(source); err != nil {
			return fmt.Errorf("mount source %s: %w", source, err)
		}
	}
	return nil
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
