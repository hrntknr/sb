package awsproxy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/hrntknr/sb/internal/util"
)

var errConflictingRoles = errors.New("aws: matching profiles have different roleArn values")
var roleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov):iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$`)

func ValidRoleARN(value string) bool { return roleARN.MatchString(value) }

// Target grants named AWS operations to a source profile in selected regions.
type Target struct {
	Profile  string
	RoleARN  string
	Services []Service
	Regions  []string
}

type Service struct {
	Name string
	Mode string
}

// endpoint is the mechanically resolved upstream location of one AWS service.
// Host may contain {region}; SigningRegion overrides the request region for
// global endpoints. The map keys are SigV4 signing names.
type endpoint struct {
	Host          string
	Protocol      string
	ContentType   string
	TargetPrefix  string
	SigningRegion string
}

// Protocols sb can proxy: JSON POST APIs carry the operation in X-Amz-Target,
// Query and EC2 POST APIs in a form-encoded Action parameter. REST protocols
// encode the operation in the request path sb does not forward.
var supportedProtocols = map[string]bool{"json": true, "query": true, "ec2": true}

func parseServices() (allowed map[string]map[string]bool, endpoints map[string]endpoint) {
	var services map[string]struct {
		Host          string   `json:"host"`
		Protocol      string   `json:"protocol"`
		ContentType   string   `json:"contentType"`
		TargetPrefix  string   `json:"targetPrefix,omitempty"`
		SigningRegion string   `json:"signingRegion,omitempty"`
		Read          []string `json:"read,omitempty"`
	}
	if err := json.Unmarshal(servicesJSON, &services); err != nil {
		panic("invalid embedded AWS services: " + err.Error())
	}
	allowed = map[string]map[string]bool{}
	endpoints = map[string]endpoint{}
	for service, entry := range services {
		if entry.Host == "" || entry.Protocol == "" || entry.ContentType == "" || entry.Protocol == "json" && entry.TargetPrefix == "" {
			panic("missing embedded AWS endpoint for " + service)
		}
		operations := map[string]bool{}
		for _, operation := range entry.Read {
			operations[strings.ToLower(operation)] = true
		}
		allowed[service] = operations
		endpoints[service] = endpoint{Host: entry.Host, Protocol: entry.Protocol, ContentType: entry.ContentType, TargetPrefix: entry.TargetPrefix, SigningRegion: entry.SigningRegion}
	}
	return allowed, endpoints
}

//go:embed services.json
var servicesJSON []byte

var allowedOperations, serviceEndpoints = parseServices()

func ValidService(service Service) bool {
	return ValidServiceName(service.Name) && (service.Mode == "r" || service.Mode == "rw")
}

// ValidServiceName reports whether name is an AWS service sb can forward:
// covered by the embedded service reference with a fixed or {region} host
// and a protocol sb proxies (JSON, Query, or EC2 POST).
func ValidServiceName(name string) bool {
	entry, forwardable := serviceEndpoints[name]
	_, allowed := allowedOperations[name]
	return allowed && forwardable && supportedProtocols[entry.Protocol]
}

// assumedRole returns the role ARN to assume for a profile from matching
// targets. Matching targets must agree on the role. An empty role means no
// role is assumed and the source profile's own credentials are used.
func assumedRole(targets []Target, profile string) (string, error) {
	role := ""
	for _, target := range targets {
		if !util.Match(target.Profile, profile) {
			continue
		}
		if role != "" && role != target.RoleARN {
			return "", errConflictingRoles
		}
		role = target.RoleARN
	}
	return role, nil
}

func allows(targets []Target, profile, region, action string) bool {
	service, operation, ok := strings.Cut(action, ":")
	if !ok || operation == "" {
		return false
	}
	for _, target := range targets {
		if !util.Match(target.Profile, profile) {
			continue
		}
		if len(target.Regions) > 0 {
			matched := false
			for _, pattern := range target.Regions {
				matched = matched || util.Match(pattern, region)
			}
			if !matched {
				continue
			}
		}
		for _, entry := range target.Services {
			if entry.Name != service {
				continue
			}
			if entry.Mode == "rw" {
				return true
			}
			if allowedOperations[service][strings.ToLower(operation)] {
				return true
			}
		}
	}
	return false
}

func hasProfile(targets []Target, profile string) bool {
	for _, target := range targets {
		if util.Match(target.Profile, profile) {
			return true
		}
	}
	return false
}
