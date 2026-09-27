// Package containers wraps the local container runtime (docker, podman, or
// the apple container CLI): it detects which one is installed, verifies it
// can reach the host, and builds the arguments that mount sb
// credentials into a container.
package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
// host. network is the value of the run --network flag; "host" runs the
// container in the host network namespace, where the proxy is reachable
// as localhost.
func ResolveHost(r Runtime, network string) (string, error) {
	hostNetwork := network == "host"
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
		if network != "" {
			return "", fmt.Errorf("apple: --network is not supported by the apple container CLI")
		}
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

// LabelSession is the label sb puts on the containers it manages. The value
// is the session ID that owns the container; sb finds, stops, and removes
// containers by this label (see internal/session).
const LabelSession = "sb.session.id"

// SessionLabelArg builds the --label argument value for a session ID.
func SessionLabelArg(sessionID string) string {
	return LabelSession + "=" + sessionID
}

func labelFilter(sessionID string) string { return "label=" + SessionLabelArg(sessionID) }

// ListSession returns the IDs of the containers (running or not) that carry
// the session label: the runtime's own records, not sb's, are the source of
// truth, so a session's containers are found even if its records were
// never written. ctx bounds the call: a runtime that does not answer is
// killed at its deadline.
func ListSession(ctx context.Context, r Runtime, sessionID string) ([]string, error) {
	var args []string
	if r == Apple {
		// The apple CLI's ls has no --filter; ps --filter label= covers
		// docker and podman, and the apple CLI prints its whole container
		// list as JSON.
		args = []string{"ls", "--all", "--format", "json"}
	} else {
		args = []string{"ps", "-aq", "--filter", labelFilter(sessionID)}
	}
	out, err := output(ctx, r, args)
	if err != nil {
		if r == Apple {
			return nil, fmt.Errorf("%s: cannot list by session label: %w", r, err)
		}
		return nil, fmt.Errorf("%s: cannot list by session label (is the runtime running?): %w", r, err)
	}
	if r == Apple {
		return labelMatches(out, sessionID)
	}
	return nonEmpty(out), nil
}

// output runs the runtime CLI for its output. The wait past the command's
// exit is bounded by WaitDeadline: without it a child of the CLI holding
// the pipes keeps the read open past the context's kill.
func output(ctx context.Context, r Runtime, args []string) ([]byte, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, r.Binary(), args...)
	cmd.WaitDelay = WaitDeadline
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// WaitDeadline bounds each runtime CLI call's wait past its exit: a child
// of the CLI holding stdout/stderr open keeps the call waiting for EOF
// past the context's kill — this returns it.
const WaitDeadline = 5 * time.Second

// labelMatches selects container IDs whose labels carry the session ID from
// the apple CLI's JSON list output.
func labelMatches(out []byte, sessionID string) ([]string, error) {
	var containers []struct {
		ID            string `json:"id"`
		Configuration struct {
			Labels map[string]string `json:"labels"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(out, &containers); err != nil {
		return nil, fmt.Errorf("apple: parse container list: %w", err)
	}
	var ids []string
	for _, c := range containers {
		if c.Configuration.Labels[LabelSession] == sessionID {
			ids = append(ids, c.ID)
		}
	}
	return ids, nil
}

func nonEmpty(out []byte) []string {
	var ids []string
	for _, line := range strings.Split(string(out), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// RemoveSession stops and removes the containers that carry the session
// label (`rm -f`, which stops running containers first). A container that
// the runtime no longer knows (already removed) is not an error: the
// listing is the source of truth, not sb's records. What the runtime
// answers without removing is a failed removal: the listing after it
// must come back empty, and it is an error when it does not.
//
// found reports whether the first listing saw any container of the
// session: what the runtime has committed. For a creation whose result
// is not fixed, that listing is the only confirmation of its end — one
// create commits exactly one container, so nothing of it can appear
// after the removal of what it committed.
func RemoveSession(ctx context.Context, r Runtime, sessionID string) (found bool, err error) {
	ids, err := ListSession(ctx, r, sessionID)
	if err != nil {
		return false, err
	}
	return len(ids) > 0, RemoveListed(ctx, r, sessionID, ids)
}

// RemoveListed removes the listed containers and verifies the session's
// listing comes back empty: what the listing that found them started
// must be gone when it ends. It is the half of RemoveSession after the
// listing: whoever observes the listing itself (a removal that settles
// what it found) runs this with what it saw.
func RemoveListed(ctx context.Context, r Runtime, sessionID string, ids []string) error {
	for _, id := range ids {
		if err := RemoveByID(ctx, r, id); err != nil {
			return err
		}
	}
	left, err := ListSession(ctx, r, sessionID)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("%s: remove left containers behind: %s", r, strings.Join(left, " "))
	}
	return nil
}

// RemoveByID stops and removes the container with the given ID. The output
// is included verbatim: it is the recovery hint for a manual retry. ctx
// bounds the call: a runtime that does not answer is killed at its
// deadline, and WaitDeadline returns the pipe wait past it.
func RemoveByID(ctx context.Context, r Runtime, id string) error {
	cmd := exec.CommandContext(ctx, r.Binary(), "rm", "-f", id)
	cmd.WaitDelay = WaitDeadline
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: remove %s: %w: %s", r, id, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// VerifySession reports whether the container with the given ID exists and
// carries the session label, cross-checking the runtime's records against
// the session record: a stale or copied record alone connects to nothing.
// ctx bounds the call: a runtime that does not answer is killed at its
// deadline.
func VerifySession(ctx context.Context, r Runtime, containerID, sessionID string) (bool, error) {
	if containerID == "" || strings.ContainsAny(containerID, " \t\n\r") {
		return false, nil
	}
	if r == Apple {
		args := []string{"ls", "--all", "--format", "json"}
		out, err := output(ctx, r, args)
		if err != nil {
			return false, fmt.Errorf("%s: cannot list by session label: %w", r, err)
		}
		matches, err := labelMatches(out, sessionID)
		if err != nil {
			return false, err
		}
		for _, id := range matches {
			if strings.HasPrefix(strings.ToLower(containerID), strings.ToLower(id)) {
				return true, nil
			}
		}
		return false, nil
	}
	args := []string{"ps", "-aq", "--filter", "id=" + containerID, "--filter", labelFilter(sessionID)}
	out, err := output(ctx, r, args)
	if err != nil {
		return false, fmt.Errorf("%s: cannot list by session label (is the runtime running?): %w", r, err)
	}
	return len(nonEmpty(out)) > 0, nil
}

// Parse resolves a --runtime flag value, verifying the binary is installed.
func Parse(name string) (Runtime, error) {
	r, err := ParseName(name)
	if err != nil {
		return "", err
	}
	if _, err := exec.LookPath(r.Binary()); err != nil {
		return "", fmt.Errorf("%s: %w", r, err)
	}
	return r, nil
}

// ParseName resolves a --runtime flag value without requiring the binary
// to be installed: the recovery advice names the CLI to run by hand,
// whether or not sb can run it.
func ParseName(name string) (Runtime, error) {
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
	return r, nil
}

// Protocol identifies a credential protocol sb issues: the proxy serves
// it and the container mounts the credentials under /root for it. The
// zero value is no protocol — nothing is served, issued, or mounted.
type Protocol uint8

const (
	ProtocolSSH Protocol = 1 << iota
	ProtocolK8s
	ProtocolAWS
)

// CreateArgs builds the runtime CLI arguments that create the container
// stopped — nothing runs yet. The sb credentials under dir are mounted
// at /root (read-only) for the protocols in use: a protocol without
// rules issues nothing, so nothing is mounted under its name either.
// The user's own arguments are the container's command, and the session
// label marks it as sb's to stop and remove. The runtime records the
// container ID in a cidfile under dir once the container exists.
//
// host is the value ResolveHost returned. name and network, when
// non-empty, are passed to the runtime as --name and --network. envs are
// environment variables (KEY=VALUE, or just KEY to inherit from sb's own
// environment). mounts are extra "source:target" volumes, with ~ already
// expanded and ":ro" appended for read-only mounts. labels are --label
// arguments. image is inserted before userArgs, which form the container
// command. init, when set, passes --init so the command runs under an
// init process as PID 1 that forwards signals and reaps zombies, which
// the user's command (a shell, node, ...) would not do on its own.
func CreateArgs(r Runtime, host, dir string, protocols Protocol, name, network string, envs []string, tty bool, mounts, labels []string, image string, init bool, userArgs []string) []string {
	args := []string{"create", "--cidfile", CidFile(dir)}
	if init {
		args = append(args, "--init")
	}
	if name != "" {
		args = append(args, "--name", name)
	}
	if network != "" {
		args = append(args, "--network", network)
	}
	for _, env := range envs {
		args = append(args, "--env", env)
	}
	for _, label := range labels {
		args = append(args, "--label", label)
	}
	if r == Docker && host == dockerHost {
		args = append(args, "--add-host", dockerHost+":host-gateway")
	}
	if protocols&ProtocolSSH != 0 {
		args = append(args, "-v", filepath.Join(dir, ".ssh")+":/root/.ssh:ro")
	}
	if protocols&ProtocolK8s != 0 {
		args = append(args, "-v", filepath.Join(dir, ".kube")+":/root/.kube:ro")
	}
	if protocols&ProtocolAWS != 0 {
		args = append(args, "-v", filepath.Join(dir, ".aws")+":/root/.aws:ro")
	}
	for _, mount := range mounts {
		args = append(args, "-v", mount)
	}
	if tty {
		args = append(args, "-i", "-t")
	}
	return append(append(args, image), userArgs...)
}

// ExecArgs builds the runtime CLI arguments that run command inside the
// container identified by container — the ID from the session record, not
// the container name: a name that another container took over must not be
// reachable through sb's records. workdir, when non-empty, sets the
// working directory (-w/--workdir).
func ExecArgs(container, workdir string, tty bool, command []string) []string {
	args := []string{"exec"}
	if tty {
		args = append(args, "-i", "-t")
	}
	if workdir != "" {
		args = append(args, "-w", workdir)
	}
	return append(append(args, container), command...)
}

// StartArgs builds the runtime CLI arguments that start the created
// container and attach to it: the CLI's streams are the container's, its
// exit is the container's. With tty, the CLI also carries stdin to the
// container; without it, the container's stdin stays closed.
func StartArgs(id string, tty bool) []string {
	args := []string{"start", "-a"}
	if tty {
		args = append(args, "-i")
	}
	return append(args, id)
}

// ForceRemove force-removes the container whose ID CreateArgs had the
// runtime record in the cidfile under dir, stopping it if it still runs:
// killing the runtime CLI is not enough, since the container lives outside
// its process (in the docker or podman daemon, or the apple machine). A
// missing or empty cidfile — the container never started — is a no-op.
func ForceRemove(r Runtime, dir string) {
	data, err := os.ReadFile(CidFile(dir))
	if err != nil {
		return
	}
	if cid := strings.TrimSpace(string(data)); cid != "" {
		_ = exec.Command(r.Binary(), "rm", "-f", cid).Run()
	}
}

// CidFile is the path of the file the runtime records the container ID
// in: what CreateArgs passes as --cidfile, and what sb reads once the
// container exists.
func CidFile(dir string) string {
	return filepath.Join(dir, "cid")
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
