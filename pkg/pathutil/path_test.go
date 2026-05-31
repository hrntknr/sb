package pathutil

import (
	"path/filepath"
	"testing"
)

func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "home",
			path: "~",
			want: home,
		},
		{
			name: "home child",
			path: "~/.ssh/id_ed25519",
			want: filepath.Join(home, ".ssh", "id_ed25519"),
		},
		{
			name: "absolute",
			path: filepath.Join(home, "config.yaml"),
			want: filepath.Join(home, "config.yaml"),
		},
		{
			name: "relative",
			path: "config.yaml",
			want: "config.yaml",
		},
		{
			name: "other user home remains literal",
			path: "~alice/.ssh/config",
			want: "~alice/.ssh/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExpandHome(tt.path); got != tt.want {
				t.Fatalf("ExpandHome(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
