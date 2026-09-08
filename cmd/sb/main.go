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
	defaultListenAddr = ":0"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		var code *exitCodeError
		if errors.As(err, &code) {
			os.Exit(code.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// options carries the flags of the root command, which are shared by all
// subcommands through persistent flags.
type options struct {
	configPath string
	logLevel   string
	host       string
	sshListen  string
	k8sListen  string
}

func newRootCommand() *cobra.Command {
	opts := &options{}
	root := &cobra.Command{
		Use:           "sb",
		Short:         "Issue scoped ssh and k8s credentials and expose them to containers",
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&opts.configPath, "config", defaultConfigPath(), "config yaml path")
	root.PersistentFlags().StringVar(&opts.logLevel, "log-level", "silent", "log level: silent, debug, info, warn, error")
	root.AddCommand(newProxyCommand(opts), newRunCommand(opts), newExecCommand(opts))
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
