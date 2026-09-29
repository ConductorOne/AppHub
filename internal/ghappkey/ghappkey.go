// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ghappkey durably stores the admin-managed GitHub App private key in
// AWS SSM Parameter Store, as a SecureString, and resolves it back.
//
// # Two interfaces, not one, on purpose
//
// [Store] is write-only and existence-check-only. It has no method that can
// return the key's value -- Exists calls DescribeParameters, which never
// returns a parameter's value at all, not GetParameter with the value
// discarded. This is what "serve" holds: the authenticated API process that
// accepts an administrator's key upload, and which this repository's stated
// rule says must never hold source credentials. A narrow write-only type is
// how that rule stays true even if a future change to this package's own
// internals gets careless -- the compiler, not a policy an author has to
// remember, refuses to let serve's wiring call a method that returns the key.
//
// [Reader] is the read side. Only "worker" -- which already holds real AWS
// and GitHub credentials for every deploy -- is ever handed one.
//
// Both are backed by the same SSM parameter and the same IAM identity's
// ambient credentials; the split is a Go-level guarantee about which process
// can reach which operation, not an AWS-level one. The operator's own IAM
// policy for serve's task role should still be scoped to exactly
// ssm:PutParameter and ssm:DescribeParameters (never ssm:GetParameter or
// kms:Decrypt) on the configured parameter, as real defense in depth.
package ghappkey

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/conductorone/apphub/credentials"
)

// Errors are deliberately generic: this package never returns AWS's own
// error text to a caller, the same rule internal/githubapp and internal/logs
// follow for the same reason.
var (
	ErrConfiguration = errors.New("ghappkey: invalid configuration")
	ErrInvalidKey    = errors.New("ghappkey: invalid key")
	ErrUnavailable   = errors.New("ghappkey: parameter store unavailable")
	ErrNotFound      = errors.New("ghappkey: key not configured")
)

// Config names the SSM parameter the key is stored under.
type Config struct {
	// Region is the SSM region. Required.
	Region string
	// ParameterName is the exact absolute parameter path, e.g.
	// "/apphub/prod/github-app/private-key". Required.
	ParameterName string
	// KMSKeyARN is the KMS key that encrypts the parameter, as a full key or
	// alias ARN. Empty means the account's AWS-managed SSM key.
	KMSKeyARN string
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Region) == "" || strings.TrimSpace(c.ParameterName) == "" {
		return fmt.Errorf("%w: region and parameterName are required", ErrConfiguration)
	}
	return nil
}

// WriteAPI is what a Store's SSM implementation calls. It deliberately
// excludes GetParameter -- see the package doc for why.
type WriteAPI interface {
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, opts ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	DescribeParameters(ctx context.Context, in *ssm.DescribeParametersInput, opts ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
	DeleteParameter(ctx context.Context, in *ssm.DeleteParameterInput, opts ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)
}

// ReadAPI is what a Reader's SSM implementation calls.
type ReadAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Store durably persists the GitHub App private key without ever being able
// to read it back.
type Store interface {
	// Put writes key, overwriting any existing value. key must not be blank.
	Put(ctx context.Context, key credentials.Secret) error
	// Exists reports whether a key is currently stored, without reading it.
	Exists(ctx context.Context) (bool, error)
	// Delete removes the stored key. Deleting an absent key is not an error.
	Delete(ctx context.Context) error
}

// Reader resolves the durably stored key.
type Reader interface {
	// Get returns the stored key, or ErrNotFound if none is configured.
	Get(ctx context.Context) (credentials.Secret, error)
}

type ssmStore struct {
	api WriteAPI
	cfg Config
}

type ssmReader struct {
	api ReadAPI
	cfg Config
}

// NewStore loads AWS configuration from the process's ambient credential
// chain and returns a Store. It performs no network I/O of its own.
func NewStore(ctx context.Context, cfg Config) (Store, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	awscfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("%w: AWS configuration could not be loaded", ErrConfiguration)
	}
	return NewStoreWithAPI(ssm.NewFromConfig(awscfg), cfg)
}

// NewStoreWithAPI builds a Store over a caller-supplied WriteAPI, for tests.
func NewStoreWithAPI(api WriteAPI, cfg Config) (Store, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if api == nil {
		return nil, fmt.Errorf("%w: API is required", ErrConfiguration)
	}
	return &ssmStore{api: api, cfg: cfg}, nil
}

// NewReader loads AWS configuration from the process's ambient credential
// chain and returns a Reader. It performs no network I/O of its own.
func NewReader(ctx context.Context, cfg Config) (Reader, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	awscfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("%w: AWS configuration could not be loaded", ErrConfiguration)
	}
	return NewReaderWithAPI(ssm.NewFromConfig(awscfg), cfg)
}

// NewReaderWithAPI builds a Reader over a caller-supplied ReadAPI, for tests.
func NewReaderWithAPI(api ReadAPI, cfg Config) (Reader, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if api == nil {
		return nil, fmt.Errorf("%w: API is required", ErrConfiguration)
	}
	return &ssmReader{api: api, cfg: cfg}, nil
}

func (s *ssmStore) Put(ctx context.Context, key credentials.Secret) error {
	pem := credentials.Reveal(key)
	if strings.TrimSpace(pem) == "" {
		return fmt.Errorf("%w: key is required", ErrInvalidKey)
	}
	in := &ssm.PutParameterInput{
		Name:      aws.String(s.cfg.ParameterName),
		Value:     aws.String(pem),
		Type:      ssmtypes.ParameterTypeSecureString,
		Overwrite: aws.Bool(true),
	}
	if s.cfg.KMSKeyARN != "" {
		in.KeyId = aws.String(s.cfg.KMSKeyARN)
	}
	if _, err := s.api.PutParameter(ctx, in); err != nil {
		return fmt.Errorf("%w: writing the parameter failed", ErrUnavailable)
	}
	return nil
}

func (s *ssmStore) Exists(ctx context.Context) (bool, error) {
	out, err := s.api.DescribeParameters(ctx, &ssm.DescribeParametersInput{
		ParameterFilters: []ssmtypes.ParameterStringFilter{{
			Key: aws.String("Name"), Option: aws.String("Equals"), Values: []string{s.cfg.ParameterName},
		}},
	})
	if err != nil {
		return false, fmt.Errorf("%w: checking the parameter failed", ErrUnavailable)
	}
	return len(out.Parameters) > 0, nil
}

func (s *ssmStore) Delete(ctx context.Context) error {
	_, err := s.api.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: aws.String(s.cfg.ParameterName)})
	if err != nil {
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("%w: deleting the parameter failed", ErrUnavailable)
	}
	return nil
}

func (r *ssmReader) Get(ctx context.Context) (credentials.Secret, error) {
	out, err := r.api.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(r.cfg.ParameterName), WithDecryption: aws.Bool(true)})
	if err != nil {
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return credentials.Secret{}, ErrNotFound
		}
		return credentials.Secret{}, fmt.Errorf("%w: reading the parameter failed", ErrUnavailable)
	}
	if out.Parameter == nil || out.Parameter.Value == nil || strings.TrimSpace(*out.Parameter.Value) == "" {
		return credentials.Secret{}, ErrNotFound
	}
	return credentials.NewSecret(*out.Parameter.Value), nil
}
