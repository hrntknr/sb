package v3

import (
	"github.com/hrntknr/sb/internal/awsproxy"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/sshproxy"
)

// SSHTargets converts the ssh rules to proxy targets. The Host pattern is
// matched against the hostname the host-side ssh client resolves for each
// request; User and Port, when set, additionally restrict the upstream
// connection's user and port.
func (c Config) SSHTargets() sshproxy.Targets {
	targets := make(sshproxy.Targets, 0, len(c.SSH))
	for _, rule := range c.SSH {
		targets = append(targets, sshproxy.Target{
			Host: rule.Host,
			User: rule.User,
			Port: rule.Port,
		})
	}
	return targets
}

// K8sTargets converts the k8s rules to proxy targets: the context with the
// resources granted on it, each as one proxy resource.
func (c Config) K8sTargets() k8sproxy.Targets {
	targets := make(k8sproxy.Targets, 0, len(c.K8s))
	for _, rule := range c.K8s {
		resources := make([]k8sproxy.Resource, 0, len(rule.Resources))
		for _, resource := range rule.Resources {
			resources = append(resources, k8sproxy.Resource{
				Group:     resource.Group,
				Resource:  resource.Resource,
				Namespace: resource.Namespace,
				Scope:     resource.Scope,
				Verbs:     resource.Verbs,
			})
		}
		targets = append(targets, k8sproxy.Target{
			Context:   rule.Context,
			Resources: resources,
		})
	}
	return targets
}

// AWSTargets converts the aws rules to proxy targets.
func (c Config) AWSTargets() []awsproxy.Target {
	targets := make([]awsproxy.Target, 0, len(c.AWS))
	for _, rule := range c.AWS {
		targets = append(targets, awsproxy.Target{
			Profile:  rule.Profile,
			RoleARN:  rule.RoleARN,
			Regions:  rule.Regions,
			Services: rule.Services,
		})
	}
	return targets
}
