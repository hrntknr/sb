package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hrntknr/sb/internal/config/v3"
	"github.com/spf13/cobra"
)

// newConfigCommand builds `sb config`: subcommands that inspect the config.
func newConfigCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "config",
		Short:         "Inspect the sb config",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newConfigCheckCommand(opts))
	return cmd
}

// newConfigCheckCommand builds `sb config check`: static validation plus a
// listing of what the config grants.
func newConfigCheckCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate the config and list what it grants",
		Long: `Validate the config and list the issuance targets (ssh hosts, k8s
contexts, aws profiles) and the permissions granted to each.

ssh access: full covers the shell, any exec, subsystem, and TCP
forwarding. k8s rules list the resource, the namespace (or scope:
cluster), and the verbs; aws rules list the region, service, and mode.

Checks are static only: no credentials are read and no cluster is
contacted. Connect to the upstreams by running sb itself.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := v3.Load(opts.configPath)
			if err != nil {
				return err
			}
			fmt.Print(renderConfig(cfg))
			return nil
		},
	}
}

func renderConfig(cfg v3.Config) string {
	var b strings.Builder
	b.WriteString("Static checks only: no credentials are read and no cluster is contacted.\n")
	if len(cfg.SSH) > 0 {
		renderSSH(&b, cfg.SSH)
	}
	if len(cfg.K8s) > 0 {
		renderK8s(&b, cfg.K8s)
	}
	if len(cfg.AWS) > 0 {
		renderAWS(&b, cfg.AWS)
	}
	renderContainer(&b, cfg.Container)
	return b.String()
}

func renderSSH(b *strings.Builder, rules []v3.SSHRule) {
	b.WriteString("\nssh:\n")
	for _, r := range rules {
		fmt.Fprintf(b, "  - host: %s\n", r.Host)
		if r.User != "" {
			fmt.Fprintf(b, "    user: %s\n", r.User)
		}
		if r.Port != 0 {
			fmt.Fprintf(b, "    port: %d\n", r.Port)
		}
		b.WriteString("    access: full (shell, any exec, subsystem, TCP forwarding)\n")
	}
}

func renderK8s(b *strings.Builder, rules []v3.K8sRule) {
	b.WriteString("\nk8s:\n")
	for _, r := range rules {
		fmt.Fprintf(b, "  - context: %s\n", r.Context)
		for _, res := range r.Resources {
			fmt.Fprintf(b, "    - %s: %s\n", renderResource(res), strings.Join(res.Verbs, ", "))
		}
	}
}

func renderResource(r v3.ResourceRule) string {
	group := r.Group
	if group == "" {
		group = "core"
	}
	switch {
	case r.Scope == "cluster":
		return group + " " + r.Resource + " (cluster-scoped)"
	case r.Namespace == "*":
		return group + " " + r.Resource + " in * (all namespaces)"
	default:
		return group + " " + r.Resource + " in " + r.Namespace
	}
}

func renderAWS(b *strings.Builder, rules []v3.AWSRule) {
	b.WriteString("\naws:\n")
	for _, r := range rules {
		fmt.Fprintf(b, "  - profile: %s\n", r.Profile)
		if r.RoleARN != "" {
			fmt.Fprintf(b, "    roleArn: %s\n", r.RoleARN)
		} else {
			b.WriteString("    roleArn: (omitted: signs with the source profile's own credentials)\n")
		}
		if len(r.Regions) > 0 {
			fmt.Fprintf(b, "    regions: %s\n", strings.Join(r.Regions, ", "))
		} else {
			b.WriteString("    regions: (any)\n")
		}
		for _, s := range r.Services {
			fmt.Fprintf(b, "    %s: %s\n", s.Name, s.Mode)
		}
	}
}

func renderContainer(b *strings.Builder, c v3.Container) {
	if c.Image == "" && c.Runtime == "" && len(c.Mounts) == 0 && len(c.Environment) == 0 {
		return
	}
	b.WriteString("\ncontainer:\n")
	if c.Runtime != "" {
		fmt.Fprintf(b, "  runtime: %s\n", c.Runtime)
	}
	fmt.Fprintf(b, "  image: %s\n", c.Image)
	if len(c.Mounts) > 0 {
		b.WriteString("  mounts:\n")
		for _, m := range c.Mounts {
			perm := "read-write"
			if m.ReadOnly {
				perm = "read-only"
			}
			fmt.Fprintf(b, "    - %s -> %s (%s)\n", m.Source, m.Target, perm)
		}
	}
	if len(c.Environment) > 0 {
		b.WriteString("  environment:\n")
		for _, key := range slices.Sorted(maps.Keys(c.Environment)) {
			if c.Environment[key].Inherit {
				fmt.Fprintf(b, "    %s: inherit\n", key)
			} else {
				fmt.Fprintf(b, "    %s: %s\n", key, c.Environment[key].Value)
			}
		}
	}
}
