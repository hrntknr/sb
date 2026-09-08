package k8sproxy

import (
	"strings"

	"github.com/hrntknr/sb/internal/util"
)

type Verb string

const (
	Read      Verb = "r"
	ReadWrite Verb = "rw"
)

// Target grants Mode access to kubeconfig contexts matching the Context glob.
// Policy is keyed by context name, so contexts that point at the same cluster
// are isolated from each other. A nil Namespaces allows any namespace;
// otherwise only listed namespace globs are allowed. ClusterScope permits
// cluster-scoped (non-namespaced) requests.
type Target struct {
	Mode         Verb
	Context      string
	Namespaces   []string
	ClusterScope bool
}

type Targets []Target

func (t Targets) Allows(verb Verb, context, namespace string) bool {
	context = strings.TrimSpace(context)
	namespace = strings.TrimSpace(namespace)
	for _, rule := range t {
		if !verbAllowed(rule.Mode, verb) {
			continue
		}
		if !util.Match(rule.Context, context) {
			continue
		}
		if namespace == "" {
			if rule.ClusterScope {
				return true
			}
			continue
		}
		if rule.allowsNamespace(namespace) {
			return true
		}
	}
	return false
}

func (target Target) allowsNamespace(namespace string) bool {
	if target.Namespaces == nil {
		return true
	}
	for _, pattern := range target.Namespaces {
		if util.Match(pattern, namespace) {
			return true
		}
	}
	return false
}

func verbAllowed(ruleVerb, requested Verb) bool {
	switch ruleVerb {
	case ReadWrite:
		return requested == Read || requested == ReadWrite
	case Read:
		return requested == Read
	default:
		return false
	}
}
