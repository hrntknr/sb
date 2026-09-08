// Package agentenv resolves the ssh-agent socket path. An env file can be
// supplied so that restarted agents (which get a new socket path) are
// followed: the file is re-read on every lookup.
package agentenv

import (
	"os"
	"strings"

	"github.com/hrntknr/sb/internal/util"
	"mvdan.cc/sh/v3/syntax"
)

// Source resolves SSH_AUTH_SOCK. When Path is empty the process environment is
// used; otherwise the file at Path is parsed as shell source on every call, so
// a rewritten env file (e.g. after an agent restart) is picked up immediately.
type Source struct {
	Path string
}

func (s Source) SocketPath() string {
	if s.Path == "" {
		return os.Getenv("SSH_AUTH_SOCK")
	}
	content, err := os.ReadFile(s.Path)
	if err != nil {
		return ""
	}
	return parseSocketPath(string(content))
}

// parseSocketPath extracts the last SSH_AUTH_SOCK assignment from shell
// source. It understands plain and quoted assignments as well as
// "export KEY=value" lines, so both dotenv-style files and the raw output of
// ssh-agent work:
//
//	SSH_AUTH_SOCK=/tmp/agent.123; export SSH_AUTH_SOCK;
//	SSH_AGENT_PID=42; export SSH_AGENT_PID;
//	echo Agent pid 42;
func parseSocketPath(content string) string {
	file, err := syntax.NewParser().Parse(strings.NewReader(strings.ReplaceAll(content, "\r\n", "\n")), "")
	if err != nil {
		return ""
	}
	socket := ""
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Assign:
			if n.Name != nil && n.Name.Value == "SSH_AUTH_SOCK" && !n.Naked && n.Index == nil {
				// A later assignment decides the value; one whose value
				// cannot be determined (empty, expansion) clears it, so a
				// stale socket is never reused.
				if lit, ok := util.ShellWord(n.Value); ok {
					socket = lit
				} else {
					socket = ""
				}
			}
		case *syntax.CallExpr:
			if value, ok := exportAssignments(n); ok {
				socket = value
			}
		}
		return true
	})
	return socket
}

// exportAssignments returns the last SSH_AUTH_SOCK value of an "export
// KEY=value" command, so dotenv-style files are understood like ssh-agent's
// own output style. It reports false when the command assigns nothing.
func exportAssignments(call *syntax.CallExpr) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	if first, ok := util.ShellWord(call.Args[0]); !ok || first != "export" {
		return "", false
	}
	value, found := "", false
	for _, arg := range call.Args[1:] {
		text, ok := util.ShellWord(arg)
		if !ok {
			continue
		}
		if key, v, hasValue := strings.Cut(text, "="); hasValue && key == "SSH_AUTH_SOCK" {
			value, found = v, true
		}
	}
	return value, found
}
