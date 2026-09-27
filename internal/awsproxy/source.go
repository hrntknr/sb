package awsproxy

import (
	"context"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/hrntknr/sb/internal/util"
)

func loadSourceConfig(ctx context.Context, profile string) (aws.Config, error) {
	// The transport sees the session's stop: the chain resolves under
	// contexts its cache suppresses, so what the chain sends — the
	// profile's IMDS endpoint, the role's STS calls — carries the
	// session's stop instead.
	opts := []func(*config.LoadOptions) error{
		config.WithDefaultRegion("us-east-1"),
		config.WithHTTPClient(stopClient{stop: ctx, next: &http.Client{}}),
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

// stopClient carries the session's stop on what the sources send. The
// SDK resolves the chain under contexts its cache suppresses — Done
// stays nil — so the chain's calls would go out with a context nothing
// can cancel. What performs the transport sees the stop instead: what
// the session has already cancelled is refused, and what is in flight
// is cut when the stop begins.
type stopClient struct {
	stop context.Context // the session's stop: done when it begins
	next *http.Client    // what performs the transport
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
