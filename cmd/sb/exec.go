package main

import (
	"errors"
	"os"
	"os/exec"

	"github.com/hrntknr/sb/internal/config"
	"github.com/hrntknr/sb/internal/containers"
	"github.com/hrntknr/sb/internal/util"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newExecCommand builds `sb exec [--] <command>...`: run a command
// inside a container started by `sb run`.
func newExecCommand(opts *options) *cobra.Command {
	var name, workdir string
	var envFiles []string
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

  sb exec -w /work -- kubectl get pods

--env-file (repeatable) reads KEY=VALUE lines from a file and passes
them to the command with the runtime's --env, keeping secrets out of
the command's arguments:

  sb exec --env-file ~/.config/app/secrets.env -- app serve`,
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
			return execCommand(*opts, name, workdir, envFiles, args)
		},
	}
	cmd.Flags().StringVar(&name, "name", "default", "name of the container started by sb run")
	cmd.Flags().StringVarP(&workdir, "workdir", "w", "", "working directory inside the container")
	cmd.Flags().StringArrayVar(&envFiles, "env-file", nil, "read KEY=VALUE environment variables from file, passed with the runtime's --env (repeatable)")
	// Flags after the first plain argument belong to the container
	// command, not to sb.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func execCommand(opts options, name, workdir string, envFiles []string, command []string) error {
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
	var envs []string
	for _, f := range envFiles {
		entries, err := containers.EnvFile(util.ExpandHome(f))
		if err != nil {
			return err
		}
		envs = append(envs, entries...)
	}
	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	child := exec.Command(rt.Binary(), containers.ExecArgs(name, workdir, tty, envs, command)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return exitStatus(child.Run())
}
