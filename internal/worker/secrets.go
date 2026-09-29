// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

// SecretOpener decrypts a value the control plane sealed for one deployment.
// It must refuse a ciphertext sealed for any other subject.
type SecretOpener interface {
	Open(ctx context.Context, subject cp.SecretSubject, ciphertext []byte) (compute.SecretValue, error)
}

var _ deploy.SecretValueSource = (*operationStore)(nil)

// EnvSecretValues opens this deployment's sealed values. They exist in memory
// only for the duration of the deploy module's run; the record keeps
// ciphertext until finish clears it.
func (s *operationStore) EnvSecretValues(ctx context.Context, applicationID string) (map[string]compute.SecretValue, error) {
	s.mu.Lock()
	sealed, depID, appID, opener := s.dep.SealedSecrets, s.dep.ID, s.dep.ApplicationID, s.opener
	s.mu.Unlock()
	if applicationID != appID {
		return nil, cp.ErrNotFound
	}
	if len(sealed) == 0 {
		return nil, nil
	}
	if opener == nil {
		return nil, errors.New("no secret opener is configured")
	}
	values := make(map[string]compute.SecretValue, len(sealed))
	for _, v := range sealed {
		value, err := opener.Open(ctx, cp.SecretSubject{ApplicationID: applicationID, DeploymentID: depID, Name: v.Name}, v.Ciphertext)
		if err != nil {
			// The opener's error is not wrapped: a provider's message is not
			// something to persist, and the name is all an operator needs.
			return nil, fmt.Errorf("secret %s could not be decrypted", v.Name)
		}
		values[v.Name] = value
	}
	return values, nil
}
