package main

import (
	"errors"
	"os"
	"os/exec"

	"github.com/hrntknr/sb/internal/config"
	"github.com/hrntknr/sb/internal/containers"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newExecCommand builds `sb exec [--] <command>...`: run a command
// inside a container started by `sb run`.
func newExecCommand(opts *options) *cobra.Command {
	var name, workdir string
	cmd := &cobra.Command{
		Use:   "exec [--] <command>...",
		Short: "Run a command inside a container started by sb run",
		Long: `Run a command inside a container started by sb run, from
another terminal. It targets the run's --name (default "default").
The runtime is selected like sb run: container.runtime in the config
or auto-detection. The command's exit code becomes sb's. Use -- when
the command starts with -:

  sb exec zsh -l
  sb exec --name dev zsh -l
  sb exec -- claude --settings '{"sandbox":{"enabled":false}}'

--workdir sets the working directory inside the container:

  sb exec -w /work -- kubectl get pods`,
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
	cmd.Flags().StringVar(&name, "name", "default", "name of the container started by sb run")
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
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	rt, err := resolveRuntime(cfg.Container.Runtime)
	if err != nil {
		return err
	}
	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.ExecArgs(name, workdir, tty, command)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return exitStatus(child.Run())
}
