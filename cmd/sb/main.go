package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	defaultConfigDir  = "sb"
	defaultConfigFile = "config.yaml"
	// defaultListenAddr is the default listen address of the credential
	// proxies: loopback, a free port. Downstreams reach them on the same
	// host; listening beyond loopback is the --*-listen flags' call, and
	// it requires --host (the host written into the credentials they use).
	defaultListenAddr = "127.0.0.1:0"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		var code *exitCodeError
		if errors.As(err, &code) {
			// The container's exit code is sb's. What failed around it
			// (a reclamation that could not finish) is still shown.
			if rest := withoutExitCode(err); rest != nil {
				fmt.Fprintln(os.Stderr, rest)
			}
			os.Exit(code.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// withoutExitCode returns err without the exit-code part of a joined
// error: what is left is what failed around the container's exit — the
// reclamation — which the user still needs to see. The exit code alone
// (a container that exited cleanly as far as sb is concerned) shows
// nothing.
func withoutExitCode(err error) error {
	var rest []error
	dropExitCode(err, &rest)
	return errors.Join(rest...)
}

// dropExitCode flattens err, dropping the exit-code parts: they are kept
// by their code, not shown with the rest. A single-part wrapper is not
// dropped for carrying an exit code: what is left after the drop is its
// story, and the wrapper stays — the exit code inside it shows with it.
func dropExitCode(err error, rest *[]error) {
	if err == nil {
		return
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, part := range joined.Unwrap() {
			dropExitCode(part, rest)
		}
		return
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if inner := wrapped.Unwrap(); inner != nil {
			var innerRest []error
			dropExitCode(inner, &innerRest)
			if len(innerRest) == 0 {
				// The wrapper is the exit code alone: dropped.
				return
			}
		}
		*rest = append(*rest, err)
		return
	}
	if _, ok := err.(*exitCodeError); ok {
		// The exit-code part itself: dropped wherever it sits.
		return
	}
	*rest = append(*rest, err)
}

// options carries the flags of the root command, which are shared by all
// subcommands through persistent flags.
type options struct {
	configPath string
	logLevel   string
	host       string
	sshListen  string
	k8sListen  string
	awsListen  string
}

func newRootCommand() *cobra.Command {
	opts := &options{}
	root := &cobra.Command{
		Use:           "sb",
		Short:         "Issue scoped ssh, k8s, and AWS credentials to containers",
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&opts.configPath, "config", defaultConfigPath(), "config yaml path (v3 form only: version: 3)")
	root.PersistentFlags().StringVar(&opts.logLevel, "log-level", "silent", "log level: silent, debug, info, warn, error")
	root.AddCommand(newProxyCommand(opts), newRunCommand(opts), newExecCommand(opts), newConfigCommand(opts))
	return root
}

func configureLogger(levelText string) error {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelText)) {
	case "", "silent":
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(1000)})))
		return nil
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q", levelText)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return defaultConfigFile
	}
	return filepath.Join(dir, defaultConfigDir, defaultConfigFile)
}
