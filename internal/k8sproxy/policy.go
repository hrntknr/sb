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
// are isolated from each other. A nil Namespaces allows any namespace and
// cluster-scoped requests; otherwise only listed namespace globs are
// allowed and cluster-scoped requests are denied. Secret (when false) denies
// access to Secret resources.
type Target struct {
	Mode       Verb
	Context    string
	Namespaces []string
	Secret     bool
}

type Targets []Target

// Allows reports whether verb is granted to context. secret marks requests
// that access Secret resources, which the policy additionally gates on
// Secret.
func (t Targets) Allows(verb Verb, context, namespace string, secret bool) bool {
	context = strings.TrimSpace(context)
	namespace = strings.TrimSpace(namespace)
	for _, rule := range t {
		if !verbAllowed(rule.Mode, verb) {
			continue
		}
		if !util.Match(rule.Context, context) {
			continue
		}
		if secret && !rule.Secret {
			continue
		}
		if namespace == "" {
			// Cluster-scoped and non-resource requests: allowed only by
			// targets granted every namespace.
			if rule.Namespaces == nil {
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
