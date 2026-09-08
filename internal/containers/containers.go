// Package containers wraps the local container runtime (docker, podman, or
// the apple container CLI): it detects which one is installed, verifies it
// can reach the host, and builds the arguments that mount sb
// credentials into a container.
package containers

import (
	"fmt"
	"net"
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

// Hostnames a container uses to reach a proxy listening on the host.
const (
	dockerHost = "host.docker.internal"
	podmanHost = "host.containers.internal"
	appleHost  = "host.container.internal"
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

// ResolveHost verifies the runtime can reach the host and returns the
// hostname (or IP) that containers use to reach a proxy listening on the
// host. userArgs are the runtime arguments, inspected for host networking.
func ResolveHost(r Runtime, userArgs []string) (string, error) {
	hostNetwork := r != Apple && UsesHostNetwork(userArgs)
	switch r {
	case Docker:
		return resolveDockerHost(hostNetwork)
	case Podman:
		if hostNetwork {
			return "localhost", nil
		}
		if err := checkPodman(); err != nil {
			return "", err
		}
		return podmanHost, nil
	default:
		if err := checkApple(); err != nil {
			return "", err
		}
		return appleHost, nil
	}
}

func resolveDockerHost(hostNetwork bool) (string, error) {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}\n{{.SecurityOptions}}").Output()
	if err != nil {
		return "", fmt.Errorf("docker: cannot reach the daemon (is it running?): %w", err)
	}
	version := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if !strings.Contains(string(out), "rootless") {
		if hostNetwork {
			return "localhost", nil
		}
		if !versionAtLeast(version, 20, 10) {
			return "", fmt.Errorf("docker %s: 20.10+ is required for %s (host-gateway)", version, dockerHost)
		}
		return dockerHost, nil
	}
	// Rootless docker's host-gateway points inside the daemon's own network
	// namespace, where nothing on the real host is reachable. The host's
	// outbound IP is reachable from containers through slirp4netns and
	// works with both bridge and host networking.
	if ip := outboundIP(); ip != "" {
		return ip, nil
	}
	// No route: a daemon configured to map host-gateway to the host may
	// still work, so keep the default name.
	return dockerHost, nil
}

// outboundIP returns the host's source address for outbound traffic. It
// sends no packets (a UDP connect only consults the routing table) and
// returns "" when there is no route.
var outboundIP = func() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
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

// Args builds the runtime CLI arguments that run a container with the
// sb credentials under dir mounted at /root, followed by the
// user's own arguments. host is the value ResolveHost returned. mounts are
// extra "source:target" volumes. image, when non-empty, is inserted before
// userArgs, which then form the container command.
func Args(r Runtime, host, dir string, tty bool, mounts []string, image string, userArgs []string) []string {
	args := []string{"run", "--rm"}
	if r == Docker && host == dockerHost {
		args = append(args, "--add-host", dockerHost+":host-gateway")
	}
	args = append(args,
		"-v", filepath.Join(dir, ".ssh")+":/root/.ssh",
		"-v", filepath.Join(dir, ".kube")+":/root/.kube",
	)
	for _, mount := range mounts {
		args = append(args, "-v", mount)
	}
	if tty {
		args = append(args, "-i", "-t")
	}
	if image != "" {
		args = append(args, image)
	}
	return append(args, userArgs...)
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

// HasDetach reports whether args detach the container (-d, --detach). The
// run subcommand rejects this: the credentials live in a directory owned by
// the sb process, so the container cannot outlive it.
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
