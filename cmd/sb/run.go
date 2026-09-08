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
	var name, network string
	cmd := &cobra.Command{
		Use:   "run [--] <command>...",
		Short: "Run a container with sb credentials",
		Long: `Run a container with scoped ssh and k8s credentials mounted in.

The image comes from container.image in the config (required); the
runtime (docker, podman, or the apple container CLI) is detected
automatically or selected with container.runtime. Mounts configured
under container.mounts are passed as -v options.

The arguments form the container command; no arguments runs the
image's default command. Use -- when the command starts with -.
The container is named with --name (default "default") so that
sb exec can target it:

  sb run
  sb run zsh -l
  sb run -- claude --settings '{"sandbox":{"enabled":false}}'

--network selects the container's network:

  sb run --network host zsh -l`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainer(cmd, *opts, name, network, args)
		},
	}
	cmd.Flags().StringVar(&name, "name", "default", "name for the container, targeted by sb exec")
	cmd.Flags().StringVar(&network, "network", "", "network for the container (with host, the proxy is reached as localhost)")
	// Flags after the first plain argument belong to the container
	// command, not to sb.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runContainer(cmd *cobra.Command, opts options, name, network string, userArgs []string) error {
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

	dir, err := os.MkdirTemp("", "sb-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	slog.Info("running container", "runtime", rt.String(), "host", host, "dir", dir)

	ctx := cmd.Context()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	proxy, err := startProxy(ctx, opts, host, dir)
	if err != nil {
		return err
	}
	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxy.Wait() }()

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.Args(rt, host, dir, name, network, cfg.Container.Environments, tty, cfg.Container.Mounts, image, userArgs)...)
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
			containers.ForceRemove(rt, dir)
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
