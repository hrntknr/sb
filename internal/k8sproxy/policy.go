package k8sproxy

import (
	"slices"
	"strings"

	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// Resource is one granted resource: the Verbs on the resource named by
// Resource (which may carry a subresource, like "pods/log") within the
// Group ("" is the core API group). Namespace is a namespace name or
// "*" (all namespaces); Scope "cluster" marks a cluster-scoped rule
// instead of a namespace.
type Resource struct {
	Group     string
	Resource  string
	Namespace string
	Scope     string
	Verbs     []string
}

// Target grants the Resources on the kubeconfig context named Context.
// The context is both the selection in the source kubeconfig and the
// partition of the permission: the rules of one context never apply to
// another, even when both point at the same cluster.
type Target struct {
	Context   string
	Resources []Resource
}

type Targets []Target

// policyContexts returns the contexts named by the policy's targets, in
// order, without duplicates.
func policyContexts(targets Targets) []string {
	contexts := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		if target.Context == "" || seen[target.Context] {
			continue
		}
		seen[target.Context] = true
		contexts = append(contexts, target.Context)
	}
	return contexts
}

// resources returns the rules of the target that defines context, nil
// when none of them defines it.
func (t Targets) resources(context string) []Resource {
	for _, target := range t {
		if target.Context == context {
			return target.Resources
		}
	}
	return nil
}

// Allows reports whether the request is covered by the rules of the
// context the token was issued for: the group, resource, subresource,
// verb, and namespace of the request must each be granted. Non-resource
// requests are covered by the fixed discovery paths only, and only as
// GET; anything the rules or paths do not cover is rejected before it
// reaches the upstream.
func (t Targets) Allows(context string, info *apirequest.RequestInfo) bool {
	rules := t.resources(context)
	if rules == nil {
		return false
	}
	if !info.IsResourceRequest {
		return info.Verb == "get" && allowedDiscoveryPath(info.Path)
	}
	for _, rule := range rules {
		if ruleAllows(rule, info) {
			return true
		}
	}
	return false
}

// ruleAllows reports whether one rule covers the request: the group, the
// resource with its subresource, the verb, and the namespace must each
// be granted.
func ruleAllows(rule Resource, info *apirequest.RequestInfo) bool {
	if rule.Group != info.APIGroup {
		return false
	}
	resource, subresource, _ := strings.Cut(rule.Resource, "/")
	if info.Resource != resource || info.Subresource != subresource {
		return false
	}
	if !slices.Contains(rule.Verbs, info.Verb) {
		return false
	}
	return namespaceAllowed(rule, info.Namespace)
}

// namespaceAllowed reports whether the request's namespace is covered:
// a namespaced request passes in the rule's namespace (or any namespace,
// with "*"), and a request without a namespace — all namespaces, or a
// cluster-scoped one — passes only an explicit "*" or a cluster rule.
func namespaceAllowed(rule Resource, namespace string) bool {
	if namespace == "" {
		return rule.Scope == "cluster" || rule.Namespace == "*"
	}
	return rule.Namespace == "*" || rule.Namespace == namespace
}
