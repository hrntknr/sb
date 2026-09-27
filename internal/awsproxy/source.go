package awsproxy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/hrntknr/sb/internal/util"
)

func loadSourceConfig(ctx context.Context, profile string) (aws.Config, error) {
	// The chain resolves under contexts its cache suppresses, so the
	// transport carries the session's stop instead: the clients the
	// chain builds its fetches with — the container credentials
	// endpoint, the IMDS fallback — are set here, before the chain
	// build. The load's own HTTPClient stays the SDK's, so the CA
	// bundle resolves into it: a BuildableClient, not a wrapper.
	opts := []func(*config.LoadOptions) error{
		config.WithDefaultRegion("us-east-1"),
		config.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
			o.HTTPClient = stopClient{stop: ctx, next: &http.Client{}}
		}),
		config.WithEC2RoleCredentialOptions(func(o *ec2rolecreds.Options) {
			o.Client = imds.New(imdsOptions(ctx))
		}),
	}
	if profile != "default" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	} else {
		files := sourceFiles()
		_, err := config.LoadSharedConfigProfile(ctx, profile, func(o *config.LoadSharedConfigOptions) {
			o.ConfigFiles = files[:1]
			o.CredentialsFiles = files[1:]
		})
		var missing config.SharedConfigProfileNotExistError
		switch {
		case err == nil:
			opts = append(opts, config.WithSharedConfigProfile(profile))
		case errors.As(err, &missing):
			opts = append(opts, config.WithSharedConfigFiles([]string{}), config.WithSharedCredentialsFiles([]string{}))
		default:
			return aws.Config{}, err
		}
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}
	// The session's own STS client: the role's calls go over the
	// loaded transport — the CA bundle's roots when one is set, the
	// SDK's default client otherwise — carrying the session's stop
	// from here on.
	transport := cfg.HTTPClient
	if transport == nil {
		transport = awshttp.NewBuildableClient()
	}
	cfg.HTTPClient = stopClient{stop: ctx, next: transport}
	return cfg, nil
}

// imdsOptions builds the chain's IMDS client for ctx: the stop on
// what it sends. The endpoint and the disablement are left to imds.New
// itself — it resolves them from the same environment the chain's
// own client would — while the mode and the fallback are set here:
// New does not resolve those.
func imdsOptions(ctx context.Context) imds.Options {
	return imds.Options{
		EndpointMode:   endpointModeFromEnv(),
		EnableFallback: enableFallbackFromEnv(),
		HTTPClient:     stopClient{stop: ctx, next: &http.Client{}},
	}
}

// endpointModeFromEnv returns the IMDS endpoint selection the env
// config resolves: the IPv6 endpoint when asked for, the IPv4 default
// otherwise.
func endpointModeFromEnv() imds.EndpointModeState {
	if strings.EqualFold(os.Getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE"), "IPv6") {
		return imds.EndpointModeStateIPv6
	}
	return imds.EndpointModeStateUnset
}

// enableFallbackFromEnv returns the IMDSv1 fallback state the env
// config resolves: the fallback off when the v1 client is disabled,
// on when it is not, the default when unset.
func enableFallbackFromEnv() aws.Ternary {
	switch v := os.Getenv("AWS_EC2_METADATA_V1_DISABLED"); {
	case strings.EqualFold(v, "true"):
		return aws.FalseTernary
	case strings.EqualFold(v, "false"):
		return aws.TrueTernary
	}
	return aws.UnknownTernary
}

// stopClient carries the session's stop on what the sources send. The
// SDK resolves the chain under contexts its cache suppresses — Done
// stays nil — so the chain's calls would go out with a context nothing
// can cancel. What performs the transport sees the stop instead: what
// the session has already cancelled is refused, and what is in flight
// is cut when the stop begins.
type stopClient struct {
	stop context.Context   // the session's stop: done when it begins
	next config.HTTPClient // what performs the transport
}

func (c stopClient) Do(r *http.Request) (*http.Response, error) {
	// What the session already cancelled never goes out.
	if err := c.stop.Err(); err != nil {
		return nil, err
	}
	// The request carries a context the chain suppressed: the one the
	// cache resolved under, whose Done never fires. What performs the
	// transport carries the session's stop — what is in flight is cut
	// when the stop begins.
	return c.next.Do(r.Clone(util.StoppedContext(c.stop, r.Context())))
}
