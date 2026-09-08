package agentenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketPathFallsBackToEnvironment(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/from-env")
	if got := (Source{}).SocketPath(); got != "/tmp/from-env" {
		t.Fatalf("SocketPath() = %q, want /tmp/from-env", got)
	}
}

func TestSocketPathReadsEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	content := "export SSH_AUTH_SOCK=/tmp/agent.123\nexport SSH_AGENT_PID=42\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if got := (Source{Path: path}).SocketPath(); got != "/tmp/agent.123" {
		t.Fatalf("SocketPath() = %q, want /tmp/agent.123", got)
	}
}

// Regression: the env file is re-read on every lookup, so an agent restarted
// with a new socket path is followed.
func TestSocketPathFollowsRewrittenEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	write := func(socket string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("export SSH_AUTH_SOCK="+socket+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	source := Source{Path: path}

	write("/tmp/agent.111")
	if got := source.SocketPath(); got != "/tmp/agent.111" {
		t.Fatalf("SocketPath() = %q, want /tmp/agent.111", got)
	}

	write("/tmp/agent.222")
	if got := source.SocketPath(); got != "/tmp/agent.222" {
		t.Fatalf("SocketPath() after rewrite = %q, want /tmp/agent.222", got)
	}
}

func TestSocketPathMissingFile(t *testing.T) {
	if got := (Source{Path: filepath.Join(t.TempDir(), "absent.env")}).SocketPath(); got != "" {
		t.Fatalf("SocketPath() = %q, want empty", got)
	}
}

func TestParseSocketPath(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "ssh-agent output",
			content: "SSH_AUTH_SOCK=/home/user/.ssh/agent/s.t7AQsJodyv.agent.cqGrAfA0Uk; export SSH_AUTH_SOCK;\n" +
				"SSH_AGENT_PID=248527; export SSH_AGENT_PID;\n" +
				"echo Agent pid 248527; \n",
			want: "/home/user/.ssh/agent/s.t7AQsJodyv.agent.cqGrAfA0Uk",
		},
		{
			name:    "ssh-agent -s with semicolons",
			content: "SSH_AUTH_SOCK=/tmp/agent.123; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=42; export SSH_AGENT_PID;\necho Agent pid 42;\n",
			want:    "/tmp/agent.123",
		},
		{
			name:    "plain assignment",
			content: "SSH_AUTH_SOCK=/tmp/a.1\n",
			want:    "/tmp/a.1",
		},
		{
			name:    "export key value",
			content: "export SSH_AUTH_SOCK=/tmp/a.2\n",
			want:    "/tmp/a.2",
		},
		{
			name:    "export empty assignment clears earlier value",
			content: "export SSH_AUTH_SOCK=/tmp/old\nexport SSH_AUTH_SOCK=\n",
			want:    "",
		},
		{
			name:    "export with other variables",
			content: "export PATH=/usr/bin\nexport SSH_AUTH_SOCK=/tmp/a.3\nexport EDITOR=vim\n",
			want:    "/tmp/a.3",
		},
		{
			name:    "double quoted",
			content: "export SSH_AUTH_SOCK=\"/tmp/a 4\"\n",
			want:    "/tmp/a 4",
		},
		{
			name:    "single quoted",
			content: "SSH_AUTH_SOCK='/tmp/a.5'; export SSH_AUTH_SOCK;\n",
			want:    "/tmp/a.5",
		},
		{
			name:    "last assignment wins",
			content: "SSH_AUTH_SOCK=/tmp/old\nSSH_AUTH_SOCK=/tmp/new\n",
			want:    "/tmp/new",
		},
		{
			name:    "empty assignment",
			content: "SSH_AUTH_SOCK=\n",
			want:    "",
		},
		{
			name:    "later empty assignment clears earlier value",
			content: "SSH_AUTH_SOCK=/tmp/old\nSSH_AUTH_SOCK=\n",
			want:    "",
		},
		{
			name:    "later unparseable assignment clears earlier value",
			content: "SSH_AUTH_SOCK=/tmp/old\nSSH_AUTH_SOCK=$(cat /tmp/sock)\n",
			want:    "",
		},
		{
			name:    "command substitution is rejected",
			content: "SSH_AUTH_SOCK=$(cat /tmp/sock)\n",
			want:    "",
		},
		{
			name:    "variable expansion is rejected",
			content: "SSH_AUTH_SOCK=$SOCK\n",
			want:    "",
		},
		{
			name:    "only other variables",
			content: "export SSH_AGENT_PID=42\n",
			want:    "",
		},
		{
			name:    "crlf line endings",
			content: "SSH_AUTH_SOCK=/tmp/a.6; export SSH_AUTH_SOCK;\r\n",
			want:    "/tmp/a.6",
		},
		{
			name:    "garbage",
			content: "!!!not shell!!!\n",
			want:    "",
		},
		{
			name:    "empty",
			content: "",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSocketPath(tt.content); got != tt.want {
				t.Fatalf("parseSocketPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
