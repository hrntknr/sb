package sshproxy

import (
	"strings"

	"github.com/hrntknr/sb/internal/util"
)

// Target grants access to one upstream: the Host pattern is matched
// against the hostname the host-side ssh client resolves for the request,
// with the resolved user and port when User and Port are set.
type Target struct {
	Host string
	User string
	Port int
}

type Targets []Target

// Allows reports whether the upstream connection the resolved ssh config
// describes is covered: the resolved hostname must match the Host pattern,
// and a restricted user or port must equal the connection's. An empty
// target set denies everything.
func (t Targets) Allows(host, user string, port int) bool {
	host = strings.TrimSpace(host)
	for _, rule := range t {
		if !util.Match(rule.Host, host) {
			continue
		}
		if rule.User != "" && rule.User != user {
			continue
		}
		if rule.Port != 0 && rule.Port != port {
			continue
		}
		return true
	}
	return false
}
