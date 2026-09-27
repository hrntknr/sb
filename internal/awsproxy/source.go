package awsproxy

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/smithy-go/middleware"
	"github.com/hrntknr/sb/internal/util"
)

func loadSourceConfig(ctx context.Context, profile string) (aws.Config, error) {
	// The chain resolves under contexts its cache suppresses, so the
	// middleware here carries the session's stop instead: the options
	// are set before the load, and every client it builds — the
	// chain's own: the container credentials endpoint, the IMDS
	// transport, the STS of the role's assumption — inherits them
	// with the API options the SDK resolves into its config. The
	// SDK's own resolution stays whole: the CA bundle resolves into
	// the transport it loads, the shared config's IMDS settings into
	// the IMDS client the chain builds itself.
	opts := []func(*config.LoadOptions) error{
		config.WithDefaultRegion("us-east-1"),
		config.WithAPIOptions(stopAPIOptions(ctx)),
		config.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
			o.APIOptions = stopAPIOptions(ctx)
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
	return config.LoadDefaultConfig(ctx, opts...)
}

// stopAPIOptions returns the options the clients this load builds
// run per request: the context each request carries is replaced with
// one that is done when the session's stop begins. The SDK resolves
// the chain under contexts its cache suppresses — Done stays nil —
// so the chain's calls would go out with a context nothing can
// cancel. The middleware runs in every client the load builds: the
// chain's own — the container credentials endpoint, the IMDS
// transport, the STS of the role's assumption — and the session's.
func stopAPIOptions(stop context.Context) []func(*middleware.Stack) error {
	return []func(*middleware.Stack) error{
		func(stack *middleware.Stack) error {
			return stack.Build.Add(middleware.BuildMiddlewareFunc("stop", func(
				ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler,
			) (middleware.BuildOutput, middleware.Metadata, error) {
				// The request carries a context the chain suppressed:
				// the one the cache resolved under, whose Done never
				// fires. What the transport carries instead is the
				// session's stop — what the session has already
				// cancelled is refused, what is in flight is cut when
				// the stop begins.
				return next.HandleBuild(util.StoppedContext(stop, ctx), in)
			}), middleware.After)
		},
	}
}
