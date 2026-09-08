// Package containers wraps the local container runtime (docker, podman, or
// the apple container CLI): it detects which one is installed, verifies it
// can reach the host, and builds the arguments that mount secretbridge
// credentials into a container.
package containers

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Runtime is a supported container runtime.
type Runtime string

const (
	Docker Runtime = "docker"
	Podman Runtime = "podman"
	Apple  Runtime = "apple"
)

var detectOrder = []Runtime{Docker, Podman, Apple}

func (r Runtime) String() string { return string(r) }

// Binary returns the runtime's executable name.
func (r Runtime) Binary() string {
	if r == Apple {
		return "container"
	}
	return string(r)
}

// Host returns the hostname a container uses to reach a proxy listening on
// the host.
func (r Runtime) Host() string {
	switch r {
	case Docker:
		return "host.docker.internal"
	case Podman:
		return "host.containers.internal"
	default:
		return "host.container.internal"
	}
}

// Detect returns the first runtime found on PATH, preferring docker, then
// podman, then the apple container CLI.
func Detect() (Runtime, error) {
	for _, r := range detectOrder {
		if _, err := exec.LookPath(r.Binary()); err == nil {
			return r, nil
		}
	}
	return "", fmt.Errorf("no container runtime found (looked for docker, podman, container)")
}

// Parse resolves a --runtime flag value, verifying the binary is installed.
func Parse(name string) (Runtime, error) {
	var r Runtime
	switch name {
	case "docker":
		r = Docker
	case "podman":
		r = Podman
	case "apple":
		r = Apple
	default:
		return "", fmt.Errorf("unknown runtime %q (want docker, podman, or apple)", name)
	}
	if _, err := exec.LookPath(r.Binary()); err != nil {
		return "", fmt.Errorf("%s: %w", r, err)
	}
	return r, nil
}

// Check verifies the runtime is running and that containers can resolve
// Host() to reach the host.
func (r Runtime) Check() error {
	switch r {
	case Docker:
		return checkDocker()
	case Podman:
		return checkPodman()
	default:
		return checkApple()
	}
}

func checkDocker() error {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	if err != nil {
		return fmt.Errorf("docker: cannot reach the daemon (is it running?): %w", err)
	}
	version := strings.TrimSpace(string(out))
	if !versionAtLeast(version, 20, 10) {
		return fmt.Errorf("docker %s: 20.10+ is required for host.docker.internal (host-gateway)", version)
	}
	return nil
}

func checkPodman() error {
	out, err := exec.Command("podman", "info", "--format", "{{.Host.Security.Rootless}} {{.Version.Version}}").Output()
	if err != nil {
		return fmt.Errorf("podman: cannot run podman info (is the machine running?): %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 2 && fields[0] == "true" && !versionAtLeast(fields[1], 5, 3) {
		return fmt.Errorf("podman %s: rootless podman 5.3+ is required for host.containers.internal with the default pasta network; upgrade podman or pass --network host", fields[1])
	}
	return nil
}

func checkApple() error {
	out, err := exec.Command("container", "system", "dns", "list").Output()
	if err != nil {
		return fmt.Errorf("container: cannot run `container system dns list` (run `container system start` first?): %w", err)
	}
	if !strings.Contains(string(out), "host.container.internal") {
		return fmt.Errorf("container: host.container.internal is not set up; run:\n  sudo container system dns create host.container.internal --localhost 203.0.113.113")
	}
	return nil
}

// Args builds the runtime CLI arguments that run a container with the
// secretbridge credentials under dir mounted at /root, followed by the
// user's own arguments.
func Args(r Runtime, dir string, tty bool, userArgs []string) []string {
	args := []string{"run", "--rm"}
	if r == Docker {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	args = append(args,
		"-v", filepath.Join(dir, ".ssh")+":/root/.ssh",
		"-v", filepath.Join(dir, ".kube")+":/root/.kube",
	)
	if tty {
		args = append(args, "-i", "-t")
	}
	return append(args, userArgs...)
}

// HasDetach reports whether args detach the container (-d, --detach). The
// run subcommand rejects this: the credentials live in a directory owned by
// the secretbridge process, so the container cannot outlive it.
func HasDetach(args []string) bool {
	for _, arg := range args {
		if arg == "-d" || arg == "--detach" || strings.HasPrefix(arg, "--detach=") {
			return true
		}
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.ContainsRune(arg, 'd') {
			return true
		}
	}
	return false
}

// UsesHostNetwork reports whether args run the container in the host
// network namespace (docker and podman), where the proxy is reachable as
// localhost instead of Host().
func UsesHostNetwork(args []string) bool {
	for i, arg := range args {
		if (arg == "--net" || arg == "--network") && i+1 < len(args) && args[i+1] == "host" {
			return true
		}
		if arg == "--net=host" || arg == "--network=host" {
			return true
		}
	}
	return false
}

// versionAtLeast reports whether a dotted version like "20.10.12" is at
// least major.minor. Unparsable or missing parts count as zero.
func versionAtLeast(version string, major, minor int) bool {
	parts := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3)
	at := func(i int) int {
		if i >= len(parts) {
			return 0
		}
		n, _ := strconv.Atoi(parts[i])
		return n
	}
	return at(0) > major || (at(0) == major && at(1) >= minor)
}
