package containers

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEnvFile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"entry per line", "FOO=bar\nBAZ=qux\n", []string{"FOO=bar", "BAZ=qux"}},
		{"no trailing newline", "FOO=bar", []string{"FOO=bar"}},
		{"comments and blanks", "# comment\n\n   \n  # indented comment\nFOO=bar\n", []string{"FOO=bar"}},
		{"empty value", "FOO=\n", []string{"FOO="}},
		{"value keeps inner equals", "URL=http://x/?a=b\n", []string{"URL=http://x/?a=b"}},
		{"double quotes stripped", "FOO=\"bar baz\"\n", []string{"FOO=bar baz"}},
		{"single quotes stripped", "FOO='bar'\n", []string{"FOO=bar"}},
		{"unmatched quote kept", "FOO=\"bar\n", []string{"FOO=\"bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "env")
			if err := os.WriteFile(path, []byte(tt.input), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := EnvFile(path)
			if err != nil {
				t.Fatalf("EnvFile() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EnvFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnvFileErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"line without equals", "FOOBAR\n"},
		{"empty key", "=bar\n"},
		{"key with space", "FOO BAR=x\n"},
		{"quoted key", "\"FOO\"=x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "env")
			if err := os.WriteFile(path, []byte(tt.input), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := EnvFile(path); err == nil {
				t.Errorf("EnvFile() succeeded, want an error")
			}
		})
	}
}

func TestEnvFileMissing(t *testing.T) {
	if _, err := EnvFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Errorf("EnvFile() succeeded, want an error")
	}
}
