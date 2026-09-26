package v3

import (
	"github.com/hrntknr/sb/internal/awsproxy"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/sshproxy"
)

// SSHTargets converts the ssh rules to proxy targets. v3 grants access: full
// (shell, any exec, subsystem, and TCP forwarding), which the proxy enforces
// with its unrestricted capability set; the per-request user/port
// restrictions are Phase 3.
func (c Config) SSHTargets() sshproxy.Targets {
	targets := make(sshproxy.Targets, 0, len(c.SSH))
	for _, rule := range c.SSH {
		targets = append(targets, sshproxy.Target{
			Host:     rule.Host,
			Commands: []string{"*"},
			Shell:    true,
			Forward:  true,
		})
	}
	return targets
}

// K8sTargets converts the k8s rules to proxy targets. The enumerated
// resources become the proxy's coarse read level until Phase 3 implements
// the per-resource classification; namespaces are unrestricted.
func (c Config) K8sTargets() k8sproxy.Targets {
	targets := make(k8sproxy.Targets, 0, len(c.K8s))
	for _, rule := range c.K8s {
		targets = append(targets, k8sproxy.Target{
			Mode:    k8sproxy.Read,
			Context: rule.Context,
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
