package sshproxy

import (
	"strings"

	"github.com/hrntknr/sb/internal/util"
	"mvdan.cc/sh/v3/syntax"
)

// Target grants access to hosts matching the Host glob. Commands lists allowed
// command patterns; when empty, any command, shell, and forwarding are allowed.
type Target struct {
	Host     string
	Commands []string
	Shell    bool
	Forward  bool
}

type Targets []Target

// Capability is the combined access granted to a host by all matching targets.
type Capability struct {
	Commands []string
	Shell    bool
	Forward  bool
}

func (t Targets) Capability(host string) Capability {
	host = strings.TrimSpace(host)
	var c Capability
	for _, rule := range t {
		if !util.Match(rule.Host, host) {
			continue
		}
		c.Commands = append(c.Commands, rule.Commands...)
		c.Shell = c.Shell || rule.Shell
		c.Forward = c.Forward || rule.Forward
	}
	return c
}

func (c Capability) Empty() bool {
	return len(c.Commands) == 0 && !c.Shell && !c.Forward
}

// AllowsExec reports whether the shell command is allowed: every sub-command
// must match a pattern, and redirections and non-literal words are rejected.
func (c Capability) AllowsExec(command string) bool {
	for _, pattern := range c.Commands {
		if strings.TrimSpace(pattern) == "*" {
			return true
		}
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}
	seen, allowed := false, true
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Redirect:
			allowed = false // restricted hosts: pure command execution only
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				return true
			}
			seen = true
			if !c.allowsTokens(callTokens(n)) {
				allowed = false
			}
		}
		return true
	})
	return seen && allowed
}

func callTokens(call *syntax.CallExpr) []string {
	var tokens []string
	for _, w := range call.Args {
		lit, ok := util.ShellWord(w)
		if !ok {
			break
		}
		tokens = append(tokens, lit)
	}
	return tokens
}

func (c Capability) allowsTokens(tokens []string) bool {
	for _, pattern := range c.Commands {
		patternTokens := strings.Fields(pattern)
		if len(patternTokens) == 0 || len(tokens) < len(patternTokens) {
			continue
		}
		ok := true
		for i, pt := range patternTokens {
			if !util.Match(pt, tokens[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
