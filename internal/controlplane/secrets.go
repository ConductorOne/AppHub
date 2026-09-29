// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/modules/deploy"
)

// Application secrets reach SSM without this process ever holding a cloud
// deploy credential and without plaintext at rest in the control-plane table.
// A value is sealed here with a key this process may only encrypt under, is
// stored as ciphertext on the one deployment that applies it, and is opened
// only by the worker, which writes it through the target's secret store and
// then clears the ciphertext. See the decision record entry
// application-secrets-reach-ssm-through-a-kms-handoff-the-api-can-only-encrypt.

// maxApplicationSecrets bounds one application's secrets. Each becomes a
// parameter, an execution-role grant, and a task-definition entry.
const maxApplicationSecrets = 50

// maxSecretValue is the SSM standard-tier limit, and also below the 4 KiB a
// single KMS Encrypt call accepts.
const maxSecretValue = 4096

// maxBatchValueBytes bounds the plaintext one deployment carries. Sealed and
// base64-encoded it must still fit, with the rest of the deployment record,
// under the 128 KiB document limit every checkpoint is written against.
const maxBatchValueBytes = 48 << 10

// SecretSealer encrypts one secret value for the one deployment that applies
// it. The ciphertext must be bound to all three identifiers, so it cannot be
// replayed into another application, secret, or deployment.
type SecretSealer interface {
	Seal(ctx context.Context, subject SecretSubject, plaintext []byte) ([]byte, error)
}

// SecretSubject names what a sealed value belongs to.
type SecretSubject struct {
	ApplicationID string
	DeploymentID  string
	Name          string
}

// WithSecretSealer enables secret changes. Without it the secrets surface is
// read-only and reports itself unavailable.
func WithSecretSealer(sealer SecretSealer) ServiceOption {
	return func(s *Service) { s.sealer = sealer }
}

// SecretEntry is one secret an application lists. It never holds a value.
type SecretEntry struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy string    `json:"updatedBy"`
}

// SealedSecret is one value in transit to the worker.
type SealedSecret struct {
	Name       string `json:"name"`
	Ciphertext []byte `json:"ciphertext"`
}

// SecretView is the safe projection of a SecretEntry.
type SecretView struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// SecretList is an application's secret names and whether they can change.
type SecretList struct {
	Items     []SecretView `json:"items"`
	Available bool         `json:"available"`
}

// SecretChange sets or deletes one secret. Value is write-only.
type SecretChange struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Value  string `json:"value,omitempty"`
}

// SecretChangesInput is a batch of changes applied by one deployment.
type SecretChangesInput struct {
	ApplicationRevision int64          `json:"applicationRevision"`
	Changes             []SecretChange `json:"changes"`
}

// Secret change actions.
const (
	SecretSet    = "set"
	SecretDelete = "delete"
)

// ListSecrets returns an application's secret names, never values.
func (s *Service) ListSecrets(ctx context.Context, p Principal, appID string) (SecretList, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return SecretList{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return SecretList{}, err
	}
	app, _, err := s.application(ctx, p, appID)
	if err != nil {
		return SecretList{}, err
	}
	items := make([]SecretView, 0, len(app.Secrets))
	for _, e := range app.Secrets {
		items = append(items, SecretView{Name: e.Name, UpdatedAt: e.UpdatedAt})
	}
	return SecretList{Items: items, Available: s.sealer != nil}, nil
}

// DeploySecretChanges applies a batch of secret changes by deploying the
// application's current revision: save and redeploy are one operation.
func (s *Service) DeploySecretChanges(ctx context.Context, p Principal, appID string, input SecretChangesInput, key string) (DeploymentAccepted, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	app, r, err := s.application(ctx, p, appID)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	if err := requireScope(p, ApplicationsWrite); err != nil {
		return DeploymentAccepted{}, err
	}
	if err := requireScope(p, DeploymentsWrite); err != nil {
		return DeploymentAccepted{}, err
	}
	if s.sealer == nil {
		return DeploymentAccepted{}, Problem(503, "secrets_unavailable", "Secret changes are not configured for this installation.")
	}
	const operation = "secrets.deploy"
	idemID, err := idempotencyID(p, operation, key)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	hash, err := requestHash(secretChangesIdentity(appID, input))
	if err != nil {
		return DeploymentAccepted{}, err
	}
	if result, found, err := s.idempotency(ctx, idemID, operation, hash); err != nil {
		return DeploymentAccepted{}, err
	} else if found {
		return s.replayedDeployment(ctx, appID, result)
	}
	if input.ApplicationRevision < 1 {
		return DeploymentAccepted{}, Problem(400, "invalid_revision", "A positive application revision is required.")
	}
	if app.Revision != input.ApplicationRevision {
		return DeploymentAccepted{}, revisionConflict()
	}
	if !app.DeletionRequestedAt.IsZero() {
		return DeploymentAccepted{}, deletionConflict()
	}
	if app.ActiveDeploymentID != "" {
		return DeploymentAccepted{}, activeConflict()
	}
	if err := validateSecretChanges(app.Secrets, input.Changes); err != nil {
		return DeploymentAccepted{}, err
	}
	if _, err := s.validate(ctx, appID, app.Input); err != nil {
		return DeploymentAccepted{}, err
	}
	prepare := func(d *DeploymentRecord, next *ApplicationRecord) error {
		sealed, err := s.seal(ctx, appID, d.ID, input.Changes)
		if err != nil {
			return err
		}
		d.SealedSecrets = sealed
		next.Secrets = applySecretChanges(next.Secrets, input.Changes, p.UserID, d.CreatedAt)
		if image, commit, ok := s.reusableImage(ctx, app); ok {
			d.Application.PinnedImage = image
			d.ResolvedCommit = commit
		}
		return nil
	}
	return s.enqueue(ctx, p, app, r, enqueueRequest{idemID: idemID, operation: operation, hash: hash, revision: input.ApplicationRevision, prepare: prepare})
}

// reusableImage returns the image and commit of the last successful deploy
// when it deployed exactly the current revision. A secret change then only
// replaces the task definition; anything else, including a failure to read
// that deployment, falls back to a full build rather than running an image
// built from a different specification.
func (s *Service) reusableImage(ctx context.Context, app ApplicationRecord) (compute.ImageRef, string, bool) {
	image := app.LastSuccessfulArtifacts.Image
	if app.LastSuccessfulDeploymentID == "" || image == "" || app.Application.Workload != deploy.WorkloadContainer {
		return "", "", false
	}
	last, _, err := s.deployment(ctx, app.LastSuccessfulDeploymentID)
	if err != nil || last.ApplicationID != app.ID || last.State != Succeeded || last.ApplicationRevision != app.Revision || last.ResolvedCommit == "" {
		return "", "", false
	}
	return image, last.ResolvedCommit, true
}

// secretChangesIdentity is what the idempotency hash covers: names and actions.
// A hash of a value, stored durably, would be an offline guessing oracle for it.
func secretChangesIdentity(appID string, input SecretChangesInput) any {
	type change struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	changes := make([]change, 0, len(input.Changes))
	for _, c := range input.Changes {
		changes = append(changes, change{Name: c.Name, Action: c.Action})
	}
	return struct {
		ApplicationID string   `json:"applicationId"`
		Revision      int64    `json:"applicationRevision"`
		Changes       []change `json:"changes"`
	}{appID, input.ApplicationRevision, changes}
}

func (s *Service) seal(ctx context.Context, appID, deploymentID string, changes []SecretChange) ([]SealedSecret, error) {
	var sealed []SealedSecret
	for _, c := range changes {
		if c.Action != SecretSet {
			continue
		}
		ciphertext, err := s.sealer.Seal(ctx, SecretSubject{ApplicationID: appID, DeploymentID: deploymentID, Name: c.Name}, []byte(c.Value))
		if err != nil || len(ciphertext) == 0 {
			return nil, Problem(503, "secrets_unavailable", "Secret values could not be encrypted. Nothing was saved or deployed.")
		}
		sealed = append(sealed, SealedSecret{Name: c.Name, Ciphertext: ciphertext})
	}
	return sealed, nil
}

func invalidSecret(field, message string) error {
	return &Error{Status: 422, Code: "invalid_secret", Message: "Secret changes are invalid. Nothing was saved or deployed.", FieldErrors: map[string]string{field: message}}
}

// validateSecretChanges checks a batch against the current names. Messages
// never include a value.
func validateSecretChanges(current []SecretEntry, changes []SecretChange) error {
	if len(changes) == 0 {
		return invalidSecret("changes", "Include at least one change.")
	}
	if len(changes) > maxApplicationSecrets {
		return invalidSecret("changes", fmt.Sprintf("Include at most %d changes.", maxApplicationSecrets))
	}
	existing := secretNames(current)
	count := len(existing)
	total := 0
	seen := map[string]bool{}
	for i, c := range changes {
		field := fmt.Sprintf("changes.%d", i)
		if seen[c.Name] {
			return invalidSecret(field+".name", c.Name+" appears more than once.")
		}
		seen[c.Name] = true
		if err := deploy.ValidateEnvSecretName(c.Name); err != nil {
			return invalidSecret(field+".name", strings.TrimPrefix(err.Error(), deploy.ErrInvalidApplication.Error()+": "))
		}
		exists := slices.Contains(existing, c.Name)
		switch c.Action {
		case SecretSet:
			if c.Value == "" || len(c.Value) > maxSecretValue {
				return invalidSecret(field+".value", fmt.Sprintf("Enter a value of 1 to %d bytes.", maxSecretValue))
			}
			total += len(c.Value)
			if !exists {
				count++
			}
		case SecretDelete:
			if c.Value != "" {
				return invalidSecret(field+".value", "A delete carries no value.")
			}
			if !exists {
				return invalidSecret(field+".name", c.Name+" is not set, so it cannot be deleted.")
			}
			count--
		default:
			return invalidSecret(field+".action", "Use set or delete.")
		}
	}
	if total > maxBatchValueBytes {
		return invalidSecret("changes", fmt.Sprintf("Values in one save total at most %d KiB. Save the rest in another deployment.", maxBatchValueBytes>>10))
	}
	if count > maxApplicationSecrets {
		return invalidSecret("changes", fmt.Sprintf("An application holds at most %d secrets.", maxApplicationSecrets))
	}
	return nil
}

func applySecretChanges(current []SecretEntry, changes []SecretChange, userID string, at time.Time) []SecretEntry {
	byName := make(map[string]SecretEntry, len(current))
	for _, e := range current {
		byName[e.Name] = e
	}
	for _, c := range changes {
		if c.Action == SecretDelete {
			delete(byName, c.Name)
			continue
		}
		byName[c.Name] = SecretEntry{Name: c.Name, UpdatedAt: at, UpdatedBy: userID}
	}
	out := make([]SecretEntry, 0, len(byName))
	for _, e := range byName {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func secretNames(entries []SecretEntry) []string {
	if len(entries) == 0 {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}
