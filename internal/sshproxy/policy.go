package sshproxy

import (
	"strings"

	"github.com/hrntknr/sb/internal/util"
)

// Target grants access to hosts matching the Host glob.
type Target struct {
	Host string
}

type Targets []Target

// Allows reports whether any target grants access to host.
func (t Targets) Allows(host string) bool {
	host = strings.TrimSpace(host)
	for _, rule := range t {
		if util.Match(rule.Host, host) {
			return true
		}
	}
	return false
}
