package k8sproxy

import (
	"maps"
	"slices"
	"strings"
)

// resourceScopes maps the resources sb decides the scope of — the
// Kubernetes stable API at v1.36 (k8s.io/api v0.36.1 registers the
// kinds) — to their scope as the Kubernetes API defines it: true —
// the objects live at the cluster's root, false — inside a
// namespace. A resource outside it is not decided at all: the config
// load rejects it, so the policy never meets a rule whose scope it
// cannot check against the resource's real one.
var resourceScopes = map[string]map[string]bool{
	"": { // the core API group
		"bindings":               false,
		"componentstatuses":      true,
		"configmaps":             false,
		"endpoints":              false,
		"events":                 false,
		"limitranges":            false,
		"namespaces":             true,
		"nodes":                  true,
		"persistentvolumeclaims": false,
		"persistentvolumes":      true,
		"pods":                   false,
		"podtemplates":           false,
		"replicationcontrollers": false,
		"resourcequotas":         false,
		"secrets":                false,
		"serviceaccounts":        false,
		"services":               false,
	},
	"apps": {
		"controllerrevisions": false,
		"daemonsets":          false,
		"deployments":         false,
		"replicasets":         false,
		"statefulsets":        false,
	},
	"rbac.authorization.k8s.io": {
		"clusterrolebindings": true,
		"clusterroles":        true,
		"rolebindings":        false,
		"roles":               false,
	},
	"admissionregistration.k8s.io": {
		"mutatingwebhookconfigurations":     true,
		"mutatingadmissionpolicies":         true,
		"mutatingadmissionpolicybindings":   true,
		"validatingwebhookconfigurations":   true,
		"validatingadmissionpolicies":       true,
		"validatingadmissionpolicybindings": true,
	},
	"apiextensions.k8s.io": {
		"customresourcedefinitions": true,
	},
	"apiregistration.k8s.io": {
		"apiservices": true,
	},
	"authentication.k8s.io": {
		"selfsubjectreviews": true,
		"tokenreviews":       true,
	},
	"authorization.k8s.io": {
		"localsubjectaccessreviews": false,
		"selfsubjectaccessreviews":  true,
		"selfsubjectrulesreviews":   true,
		"subjectaccessreviews":      true,
	},
	"autoscaling": {
		"horizontalpodautoscalers": false,
	},
	"batch": {
		"cronjobs": false,
		"jobs":     false,
	},
	"certificates.k8s.io": {
		"certificatesigningrequests": true,
	},
	"coordination.k8s.io": {
		"leases": false,
	},
	"flowcontrol.apiserver.k8s.io": {
		"flowschemas":                 true,
		"prioritylevelconfigurations": true,
	},
	"discovery.k8s.io": {
		"endpointslices": false,
	},
	"events.k8s.io": {
		"events": false,
	},
	"networking.k8s.io": {
		"ingressclasses":  true,
		"ingresses":       false,
		"ipaddresses":     true,
		"networkpolicies": false,
		"servicecidrs":    true,
	},
	"node.k8s.io": {
		"runtimeclasses": true,
	},
	"policy": {
		"poddisruptionbudgets": false,
	},
	"resource.k8s.io": {
		"deviceclasses":          true,
		"resourceclaims":         false,
		"resourceclaimtemplates": false,
		"resourceslices":         true,
	},
	"scheduling.k8s.io": {
		"priorityclasses": true,
	},
	"storage.k8s.io": {
		"csidrivers":              true,
		"csinodes":                true,
		"csistoragecapacities":    false,
		"storageclasses":          true,
		"volumeattachments":       true,
		"volumeattributesclasses": true,
	},
}

// ResourceScope returns the scope the Kubernetes API gives the resource:
// cluster-scoped (true) — the objects live at the cluster's root — or
// namespaced (false), with any subresource stripped. Only the resources
// above are decided by it; anything else (another group, or a name no
// group defines) is not, and the config load rejects it: what the policy
// sees is always decided.
func ResourceScope(group, resource string) (clusterScoped, decided bool) {
	base, _, _ := strings.Cut(resource, "/")
	resources := resourceScopes[group]
	if resources == nil {
		return false, false
	}
	clusterScoped, decided = resources[base]
	return clusterScoped, decided
}

// ScopedResource is one resource of the stable API sb decides the scope
// of: the resource name within its group ("" is the core API group) and
// whether its objects live at the cluster's root (cluster-scoped) or
// inside a namespace.
type ScopedResource struct {
	Group         string
	Resource      string
	ClusterScoped bool
}

// AllResources lists every resource of the stable API sb decides the
// scope of, sorted by group then resource. The k8s mode shorthand
// expands into a grant on each of them, at the scope shape the map
// gives it.
func AllResources() []ScopedResource {
	total := 0
	for _, resources := range resourceScopes {
		total += len(resources)
	}
	all := make([]ScopedResource, 0, total)
	for _, group := range slices.Sorted(maps.Keys(resourceScopes)) {
		for _, resource := range slices.Sorted(maps.Keys(resourceScopes[group])) {
			all = append(all, ScopedResource{
				Group:         group,
				Resource:      resource,
				ClusterScoped: resourceScopes[group][resource],
			})
		}
	}
	return all
}
