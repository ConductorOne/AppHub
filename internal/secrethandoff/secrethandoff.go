// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package secrethandoff moves an application secret value from the API process
// to the worker through the control-plane table without it ever being stored
// there in plaintext, using one symmetric KMS key.
//
// # Two types, not one, on purpose
//
// [Sealer] can only encrypt. It is what "serve" holds: the process that
// accepts a value from a browser and must never be able to read one back.
// [Opener] can only decrypt, and only "worker" -- which already holds the
// deploy credential that writes the value to SSM -- is handed one. The split is
// the same Go-level guarantee internal/ghappkey makes for the GitHub App key;
// the operator's IAM policies (encrypt-only for serve, decrypt-only for worker)
// are the AWS-level one.
//
// # Encryption context
//
// Every value is bound to the application, the secret name, and the one
// deployment that applies it. KMS refuses to decrypt under any other context,
// so a ciphertext copied into another deployment record -- even of the same
// application -- is useless, and the IAM policies require all three keys.
package secrethandoff

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
)

// Errors are deliberately generic: KMS error text is never returned to a caller.
var (
	ErrConfiguration = errors.New("secrethandoff: invalid configuration")
	ErrUnavailable   = errors.New("secrethandoff: key service unavailable")
)

// Encryption context keys. The Terraform IAM conditions name the same keys.
const (
	contextApplication = "apphub:application"
	contextSecret      = "apphub:secret"
	contextDeployment  = "apphub:deployment"
)

// EncryptAPI is the one KMS operation a Sealer uses.
type EncryptAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
}

// DecryptAPI is the one KMS operation an Opener uses.
type DecryptAPI interface {
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Sealer encrypts values for the worker. It implements controlplane.SecretSealer.
type Sealer struct {
	api   EncryptAPI
	keyID string
}

// Opener decrypts values sealed for a deployment. It implements worker.SecretOpener.
type Opener struct {
	api   DecryptAPI
	keyID string
}

var _ cp.SecretSealer = (*Sealer)(nil)

// NewSealer loads ambient AWS credentials for the key's region.
func NewSealer(ctx context.Context, keyARN string) (*Sealer, error) {
	client, err := newClient(ctx, keyARN)
	if err != nil {
		return nil, err
	}
	return NewSealerWithAPI(client, keyARN)
}

// NewSealerWithAPI builds a Sealer over a caller-supplied API, for tests.
func NewSealerWithAPI(api EncryptAPI, keyARN string) (*Sealer, error) {
	if api == nil {
		return nil, fmt.Errorf("%w: API is required", ErrConfiguration)
	}
	if _, err := Region(keyARN); err != nil {
		return nil, err
	}
	return &Sealer{api: api, keyID: keyARN}, nil
}

// NewOpener loads ambient AWS credentials for the key's region.
func NewOpener(ctx context.Context, keyARN string) (*Opener, error) {
	client, err := newClient(ctx, keyARN)
	if err != nil {
		return nil, err
	}
	return NewOpenerWithAPI(client, keyARN)
}

// NewOpenerWithAPI builds an Opener over a caller-supplied API, for tests.
func NewOpenerWithAPI(api DecryptAPI, keyARN string) (*Opener, error) {
	if api == nil {
		return nil, fmt.Errorf("%w: API is required", ErrConfiguration)
	}
	if _, err := Region(keyARN); err != nil {
		return nil, err
	}
	return &Opener{api: api, keyID: keyARN}, nil
}

func newClient(ctx context.Context, keyARN string) (*kms.Client, error) {
	region, err := Region(keyARN)
	if err != nil {
		return nil, err
	}
	awscfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("%w: AWS configuration could not be loaded", ErrConfiguration)
	}
	return kms.NewFromConfig(awscfg), nil
}

// Region returns the region of a KMS key or alias ARN, refusing anything else.
// A bare key ID or alias name is refused: the key's region would then be
// whatever the process's ambient configuration says, which is exactly the kind
// of silent default that sends a value to a key nobody meant.
func Region(keyARN string) (string, error) {
	parts := strings.SplitN(keyARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || parts[3] == "" || parts[4] == "" ||
		(!strings.HasPrefix(parts[5], "key/") && !strings.HasPrefix(parts[5], "alias/")) {
		return "", fmt.Errorf("%w: secrets.handoffKmsKeyArn must be a KMS key or alias ARN", ErrConfiguration)
	}
	return parts[3], nil
}

func encryptionContext(subject cp.SecretSubject) (map[string]string, error) {
	if subject.ApplicationID == "" || subject.DeploymentID == "" || subject.Name == "" {
		return nil, fmt.Errorf("%w: a sealed value must name its application, deployment and secret", ErrConfiguration)
	}
	return map[string]string{
		contextApplication: subject.ApplicationID,
		contextSecret:      subject.Name,
		contextDeployment:  subject.DeploymentID,
	}, nil
}

// Seal encrypts plaintext bound to subject.
func (s *Sealer) Seal(ctx context.Context, subject cp.SecretSubject, plaintext []byte) ([]byte, error) {
	ec, err := encryptionContext(subject)
	if err != nil {
		return nil, err
	}
	out, err := s.api.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(s.keyID), Plaintext: plaintext, EncryptionContext: ec})
	if err != nil || out == nil || len(out.CiphertextBlob) == 0 {
		return nil, ErrUnavailable
	}
	return out.CiphertextBlob, nil
}

// Open decrypts a ciphertext sealed for exactly subject.
func (o *Opener) Open(ctx context.Context, subject cp.SecretSubject, ciphertext []byte) (compute.SecretValue, error) {
	ec, err := encryptionContext(subject)
	if err != nil {
		return compute.SecretValue{}, err
	}
	out, err := o.api.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(o.keyID), CiphertextBlob: ciphertext, EncryptionContext: ec})
	if err != nil || out == nil || len(out.Plaintext) == 0 {
		return compute.SecretValue{}, ErrUnavailable
	}
	value := compute.NewSecretValue(string(out.Plaintext))
	clear(out.Plaintext)
	return value, nil
}
