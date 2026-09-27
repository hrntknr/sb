package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"

	"github.com/hrntknr/sb/internal/containers"
	"github.com/hrntknr/sb/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newExecCommand builds `sb exec --name name [--] <command>...`: run a
// command inside a container started by `sb run`.
func newExecCommand(opts *options) *cobra.Command {
	var name, workdir string
	cmd := &cobra.Command{
		Use:   "exec --name name [--] <command>...",
		Short: "Run a command inside a container started by sb run",
		Long: `Run a command inside a container started by sb run, from
another terminal. It targets the session its --name names: the runtime
and container ID come from that session's record, cross-checked against
the runtime's own records, so a dead session or a container that took
over the name connects to nothing. The current config is not consulted.
The command's exit code becomes sb's. Use -- when the command starts
with -:

  sb exec --name default zsh -l
  sb exec --name dev -- kubectl get pods
  sb exec --name default -w /work -- pwd

--workdir sets the working directory inside the container.`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// With interspersed flags off, cobra keeps a leading --;
			// the runtime would treat it as the command.
			if args[0] == "--" {
				args = args[1:]
			}
			if len(args) == 0 {
				return errors.New("exec: a command is required")
			}
			return execCommand(*opts, name, workdir, args)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name of the session started by sb run")
	_ = cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&workdir, "workdir", "w", "", "working directory inside the container")
	// Flags after the first plain argument belong to the container
	// command, not to sb.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func execCommand(opts options, name, workdir string, command []string) error {
	if err := configureLogger(opts.logLevel); err != nil {
		return err
	}

	sessionsDir, err := session.SessionsDir()
	if err != nil {
		return err
	}
	rec, err := session.LoadRecord(sessionsDir, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("exec: no session %q; is it running?", name)
		}
		return err
	}
	// Only a live session is exec'd into: its owner holds the lock, so the
	// record is not an orphan's leftover.
	if !session.LockHeld(sessionsDir, name) {
		return fmt.Errorf("exec: session %q is not running", name)
	}
	rt, err := containers.Parse(rec.Runtime)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), session.RuntimeWait)
	defer cancel()
	ok, err := containers.VerifySession(ctx, rt, rec.ContainerID, rec.ID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("exec: session %q has no container %q", name, rec.ContainerID)
	}

	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.ExecArgs(rec.ContainerID, workdir, tty, command)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return exitStatus(child.Run())
}
