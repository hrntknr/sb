package containers

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	tests := []struct {
		name     string
		runtime  Runtime
		host     string
		cname    string
		network  string
		envs     []string
		tty      bool
		mounts   []string
		image    string
		init     bool
		userArgs []string
		want     []string
	}{
		{
			name:     "docker via host-gateway",
			runtime:  Docker,
			host:     dockerHost,
			tty:      true,
			image:    "ghcr.io/hrntknr/sh:full",
			userArgs: []string{"zsh", "-l"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid", "--add-host", "host.docker.internal:host-gateway",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-i", "-t", "ghcr.io/hrntknr/sh:full", "zsh", "-l"},
		},
		{
			name:     "init flag comes after the cidfile",
			runtime:  Docker,
			host:     dockerHost,
			tty:      true,
			image:    "ghcr.io/hrntknr/sh:full",
			init:     true,
			userArgs: []string{"zsh", "-l"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid", "--init", "--add-host", "host.docker.internal:host-gateway",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-i", "-t", "ghcr.io/hrntknr/sh:full", "zsh", "-l"},
		},
		{
			name:     "name and network come before the image",
			runtime:  Docker,
			host:     "localhost",
			cname:    "dev",
			network:  "host",
			envs:     []string{"FOO=bar", "LANG"},
			tty:      true,
			mounts:   []string{"/home/me/.claude:/root/.claude"},
			image:    "ghcr.io/hrntknr/sh:full",
			userArgs: []string{"zsh", "-l"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid", "--name", "dev", "--network", "host",
				"--env", "FOO=bar", "--env", "LANG",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-v", "/home/me/.claude:/root/.claude",
				"-i", "-t", "ghcr.io/hrntknr/sh:full", "zsh", "-l"},
		},
		{
			name:     "docker with resolved host ip has no add-host",
			runtime:  Docker,
			host:     "192.168.1.5",
			tty:      false,
			image:    "ghcr.io/hrntknr/sh:full",
			userArgs: []string{"zsh", "-l"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"ghcr.io/hrntknr/sh:full", "zsh", "-l"},
		},
		{
			name:     "podman without tty",
			runtime:  Podman,
			host:     podmanHost,
			tty:      false,
			image:    "ghcr.io/hrntknr/sh:full",
			userArgs: []string{"npm", "install"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"ghcr.io/hrntknr/sh:full", "npm", "install"},
		},
		{
			name:     "apple tty with a command",
			runtime:  Apple,
			host:     appleHost,
			tty:      true,
			image:    "ghcr.io/hrntknr/sh:full",
			userArgs: []string{"zsh", "-l"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-i", "-t", "ghcr.io/hrntknr/sh:full", "zsh", "-l"},
		},
		{
			name:     "config mounts come after credentials and before user args",
			runtime:  Docker,
			host:     "192.168.1.5",
			tty:      true,
			mounts:   []string{"/home/me/.claude:/root/.claude", "/home/me/.config/opencode:/root/.config/opencode"},
			image:    "ghcr.io/hrntknr/sh:full",
			userArgs: []string{"zsh", "-l"},
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-v", "/home/me/.claude:/root/.claude",
				"-v", "/home/me/.config/opencode:/root/.config/opencode",
				"-i", "-t", "ghcr.io/hrntknr/sh:full", "zsh", "-l"},
		},
		{
			name:    "no args runs the image default",
			runtime: Docker,
			host:    "192.168.1.5",
			tty:     false,
			image:   "ghcr.io/hrntknr/sh:full",
			want: []string{"run", "--rm", "--cidfile", "/tmp/sb/cid",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"ghcr.io/hrntknr/sh:full"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Args(tt.runtime, tt.host, "/tmp/sb", tt.cname, tt.network, tt.envs, tt.tty, tt.mounts, tt.image, tt.init, tt.userArgs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Args() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecArgs(t *testing.T) {
	tests := []struct {
		name    string
		cname   string
		workdir string
		tty     bool
		command []string
		want    []string
	}{
		{"tty", "dev", "", true, []string{"zsh", "-l"}, []string{"exec", "-i", "-t", "dev", "zsh", "-l"}},
		{"no tty", "dev", "", false, []string{"kubectl", "get", "pods"}, []string{"exec", "dev", "kubectl", "get", "pods"}},
		{"workdir", "dev", "/work", false, []string{"pwd"}, []string{"exec", "-w", "/work", "dev", "pwd"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExecArgs(tt.cname, tt.workdir, tt.tty, tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExecArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestForceRemove(t *testing.T) {
	tests := []struct {
		name    string
		runtime Runtime
		cid     string // cidfile contents; empty means no file
		want    string // expected invocation, empty means none
	}{
		{"docker removes the recorded container", Docker, "0123456789abcdef\n", "rm -f 0123456789abcdef"},
		{"podman removes the recorded container", Podman, "0123456789abcdef\n", "rm -f 0123456789abcdef"},
		{"apple removes the recorded container", Apple, "silly-name\n", "rm -f silly-name"},
		{"missing cidfile is a no-op", Docker, "", ""},
		{"empty cidfile is a no-op", Docker, "\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.cid != "" {
				if err := os.WriteFile(filepath.Join(dir, "cid"), []byte(tt.cid), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(t.TempDir(), "calls.log")
			t.Setenv("PATH", fakeLoggingRuntimeDir(t, tt.runtime))
			t.Setenv("SB_TEST_CALLS_LOG", log)
			ForceRemove(tt.runtime, dir)
			got, _ := os.ReadFile(log)
			if got := strings.TrimSpace(string(got)); got != tt.want {
				t.Errorf("ForceRemove() invoked %q, want %q", got, tt.want)
			}
		})
	}
}

// fakeLoggingRuntimeDir returns a PATH directory whose binary for the given
// runtime appends its arguments to $SB_TEST_CALLS_LOG, one line per call.
func fakeLoggingRuntimeDir(t *testing.T, r Runtime) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$SB_TEST_CALLS_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, r.Binary()), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		version string
		major   int
		minor   int
		want    bool
	}{
		{"20.10.12", 20, 10, true},
		{"20.10", 20, 10, true},
		{"21.0.0", 20, 10, true},
		{"19.03.12", 20, 10, false},
		{"5.3.0", 5, 3, true},
		{"5.2.9", 5, 3, false},
		{"v24.0.7", 20, 10, true},
		{"20.10.24+debian", 20, 10, true},
		{"", 20, 10, false},
	}
	for _, tt := range tests {
		if got := versionAtLeast(tt.version, tt.major, tt.minor); got != tt.want {
			t.Errorf("versionAtLeast(%q, %d, %d) = %v, want %v", tt.version, tt.major, tt.minor, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	t.Setenv("PATH", fakeRuntimeDir(t))
	for _, name := range []string{"docker", "podman", "apple"} {
		if _, err := Parse(name); err != nil {
			t.Errorf("Parse(%q) error = %v", name, err)
		}
	}
	if _, err := Parse("containerd"); err == nil {
		t.Error("Parse(containerd) succeeded, want error")
	}
}

// fakeRuntimeDir returns a directory containing empty executables for every
// runtime binary, plus its path.
func fakeRuntimeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"docker", "podman", "container"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeDockerDir installs a docker binary that prints FAKE_DOCKER_INFO for
// `docker info`, and returns the directory.
func fakeDockerDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"$FAKE_DOCKER_INFO\"\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestResolveDockerHost(t *testing.T) {
	tests := []struct {
		name       string
		info       string
		network    string
		outboundIP string
		want       string
		wantErr    bool
	}{
		{
			name: "rootful bridge uses host-gateway name",
			info: "27.5.1\n[name=seccomp,profile=builtin]",
			want: dockerHost,
		},
		{
			name:    "rootful host network uses localhost",
			info:    "27.5.1\n[name=seccomp,profile=builtin]",
			network: "host",
			want:    "localhost",
		},
		{
			name:       "rootless uses the host outbound ip",
			info:       "27.5.1\n[name=rootless name=seccomp,profile=builtin]",
			outboundIP: "192.168.1.5",
			want:       "192.168.1.5",
		},
		{
			name:       "rootless host network also uses the outbound ip",
			info:       "27.5.1\n[name=rootless name=seccomp,profile=builtin]",
			network:    "host",
			outboundIP: "192.168.1.5",
			want:       "192.168.1.5",
		},
		{
			name:       "rootless without a route falls back to the name",
			info:       "27.5.1\n[name=rootless name=seccomp,profile=builtin]",
			outboundIP: "",
			want:       dockerHost,
		},
		{
			name:    "old docker rejected",
			info:    "19.03.12\n[name=seccomp,profile=builtin]",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PATH", fakeDockerDir(t))
			t.Setenv("FAKE_DOCKER_INFO", tt.info)
			original := outboundIP
			outboundIP = func() string { return tt.outboundIP }
			defer func() { outboundIP = original }()
			got, err := ResolveHost(Docker, tt.network)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ResolveHost() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveHost() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ResolveHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveHostPodmanAndApple(t *testing.T) {
	t.Run("apple rejects --network", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := ResolveHost(Apple, "host"); err == nil {
			t.Error("ResolveHost(apple, host) succeeded, want error")
		}
	})
	t.Run("podman host network skips checks", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // no podman binary: check must not run
		got, err := ResolveHost(Podman, "host")
		if err != nil {
			t.Fatalf("ResolveHost() error = %v", err)
		}
		if got != "localhost" {
			t.Errorf("ResolveHost() = %q, want localhost", got)
		}
	})
	t.Run("podman bridge runs checks", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := ResolveHost(Podman, ""); err == nil {
			t.Error("ResolveHost(podman) succeeded without podman installed, want error")
		}
	})
}

func TestDetectPrefersEarlierRuntimes(t *testing.T) {
	tests := []struct {
		name     string
		binaries []string
		want     Runtime
	}{
		{"all installed", []string{"docker", "podman", "container"}, Docker},
		{"docker missing", []string{"podman", "container"}, Podman},
		{"only apple", []string{"container"}, Apple},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tt.binaries {
				if err := os.WriteFile(filepath.Join(dir, name), nil, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", dir)
			got, err := Detect()
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("none installed", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := Detect(); err == nil {
			t.Error("Detect() succeeded, want error")
		}
	})
}
