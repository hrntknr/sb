package util

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func shellWord(t *testing.T, source string) (string, bool) {
	t.Helper()
	file, err := syntax.NewParser().Parse(strings.NewReader(source), "")
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", source, err)
	}
	var result string
	var ok bool
	syntax.Walk(file, func(node syntax.Node) bool {
		if assign, isAssign := node.(*syntax.Assign); isAssign {
			result, ok = ShellWord(assign.Value)
			return false
		}
		return true
	})
	return result, ok
}

func TestShellWord(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
		ok     bool
	}{
		{"literal", "A=cat", "cat", true},
		{"literal with path", "A=/tmp/agent.123", "/tmp/agent.123", true},
		{"single quoted", "A='a b'", "a b", true},
		{"double quoted", `A="a b"`, "a b", true},
		{"empty value has no word", "A=", "", false},
		{"variable", "A=$B", "", false},
		{"command substitution", "A=$(rm -rf /)", "", false},
		{"backtick substitution", "A=`rm -rf /`", "", false},
		{"glob is literal at parse time", "A=*", "*", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := shellWord(t, tt.source)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("ShellWord() = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestShellWordNil(t *testing.T) {
	if got, ok := ShellWord(nil); got != "" || ok {
		t.Fatalf("ShellWord(nil) = %q, %v; want empty, false", got, ok)
	}
}
