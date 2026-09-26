package awsproxy

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func loadSourceConfig(ctx context.Context, profile string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithDefaultRegion("us-east-1")}
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
