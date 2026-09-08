package containers

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestArgs(t *testing.T) {
	tests := []struct {
		name     string
		runtime  Runtime
		host     string
		tty      bool
		userArgs []string
		want     []string
	}{
		{
			name:     "docker via host-gateway",
			runtime:  Docker,
			host:     dockerHost,
			tty:      true,
			userArgs: []string{"alpine", "sh"},
			want: []string{"run", "--rm", "--add-host", "host.docker.internal:host-gateway",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-i", "-t", "alpine", "sh"},
		},
		{
			name:     "docker with resolved host ip has no add-host",
			runtime:  Docker,
			host:     "192.168.1.5",
			tty:      false,
			userArgs: []string{"alpine", "sh"},
			want: []string{"run", "--rm",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"alpine", "sh"},
		},
		{
			name:     "podman without tty",
			runtime:  Podman,
			host:     podmanHost,
			tty:      false,
			userArgs: []string{"node", "npm", "install"},
			want: []string{"run", "--rm",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"node", "npm", "install"},
		},
		{
			name:     "apple tty with user options",
			runtime:  Apple,
			host:     appleHost,
			tty:      true,
			userArgs: []string{"-v", "/work:/work", "ghcr.io/hrntknr/sh:full"},
			want: []string{"run", "--rm",
				"-v", "/tmp/sb/.ssh:/root/.ssh", "-v", "/tmp/sb/.kube:/root/.kube",
				"-i", "-t", "-v", "/work:/work", "ghcr.io/hrntknr/sh:full"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Args(tt.runtime, tt.host, "/tmp/sb", tt.tty, tt.userArgs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Args() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasDetach(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"detach short", []string{"-d", "alpine"}, true},
		{"detach long", []string{"--detach", "alpine"}, true},
		{"detach assigned", []string{"--detach=true", "alpine"}, true},
		{"detach in cluster", []string{"-itd", "alpine"}, true},
		{"detach leading cluster", []string{"-di", "alpine"}, true},
		{"no detach", []string{"-it", "alpine", "sh"}, false},
		{"detach-keys is not detach", []string{"--detach-keys", "ctrl-p", "alpine"}, false},
		{"dns long option", []string{"--dns", "8.8.8.8", "alpine"}, false},
		{"volume option", []string{"-v", "/a:/b", "alpine"}, false},
		{"command args", []string{"alpine", "sh", "-c", "echo hi"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasDetach(tt.args); got != tt.want {
				t.Errorf("HasDetach(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestUsesHostNetwork(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"net host", []string{"--net", "host", "alpine"}, true},
		{"network host", []string{"--network", "host", "alpine"}, true},
		{"net equals host", []string{"--net=host", "alpine"}, true},
		{"network equals host", []string{"--network=host", "alpine"}, true},
		{"net bridge", []string{"--net", "bridge", "alpine"}, false},
		{"network equals bridge", []string{"--network=bridge", "alpine"}, false},
		{"no network option", []string{"-it", "alpine"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UsesHostNetwork(tt.args); got != tt.want {
				t.Errorf("UsesHostNetwork(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
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
		name        string
		info        string
		hostNetwork bool
		outboundIP  string
		want        string
		wantErr     bool
	}{
		{
			name: "rootful bridge uses host-gateway name",
			info: "27.5.1\n[name=seccomp,profile=builtin]",
			want: dockerHost,
		},
		{
			name:        "rootful host network uses localhost",
			info:        "27.5.1\n[name=seccomp,profile=builtin]",
			hostNetwork: true,
			want:        "localhost",
		},
		{
			name:       "rootless uses the host outbound ip",
			info:       "27.5.1\n[name=rootless name=seccomp,profile=builtin]",
			outboundIP: "192.168.1.5",
			want:       "192.168.1.5",
		},
		{
			name:        "rootless host network also uses the outbound ip",
			info:        "27.5.1\n[name=rootless name=seccomp,profile=builtin]",
			hostNetwork: true,
			outboundIP:  "192.168.1.5",
			want:        "192.168.1.5",
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
			got, err := ResolveHost(Docker, nil)
			if tt.hostNetwork {
				got, err = ResolveHost(Docker, []string{"--network", "host"})
			}
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
	t.Run("podman host network skips checks", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // no podman binary: check must not run
		got, err := ResolveHost(Podman, []string{"--network", "host"})
		if err != nil {
			t.Fatalf("ResolveHost() error = %v", err)
		}
		if got != "localhost" {
			t.Errorf("ResolveHost() = %q, want localhost", got)
		}
	})
	t.Run("podman bridge runs checks", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := ResolveHost(Podman, nil); err == nil {
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
