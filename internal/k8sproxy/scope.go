package k8sproxy

import "strings"

// coreResourceScopes maps the core group's ("") fixed resources to
// their scope as the Kubernetes API defines it: true — the objects
// live at the cluster's root, false — inside a namespace. Only these
// resources are decided by it; anything else (another group, or a
// name the core group does not define) keeps the shape it was given.
var coreResourceScopes = map[string]bool{
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
}

// CoreResourceScope returns the scope the Kubernetes API gives the
// resource: cluster-scoped (true) — the objects live at the cluster's
// root — or namespaced (false). Only the core group's ("") fixed
// resources are decided by it, with any subresource stripped; another
// group, or a name the core group does not define, is not: (, false).
func CoreResourceScope(group, resource string) (clusterScoped, known bool) {
	if group != "" {
		return false, false
	}
	base, _, _ := strings.Cut(resource, "/")
	clusterScoped, known = coreResourceScopes[base]
	return clusterScoped, known
}
