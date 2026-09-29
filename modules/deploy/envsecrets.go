// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// Environment secrets are the application owner's own secrets: a name the
// workload reads as an environment variable and a value only the owner ever
// supplied. They differ from [Application.Secrets] in who writes them. Those
// are bound by a reference some other writer obtained; these are written by
// this module, on the deploy the owner asked for, through the same
// [secretBinder] and therefore the same ownership-tagged store as the database
// password.
//
// Each one is filed under envSecretPrefix + its variable name. The prefix keeps
// an owner's DATABASE_PASSWORD-shaped choice from ever meaning the module's own
// entry of that name, and the dot cannot appear in a variable name, so no
// variable maps onto another's entry.
const envSecretPrefix = "env."

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// maxEnvSecretName bounds a variable name. The store derives a parameter path
// from it, and a longer name would be digested into an unreadable one.
const maxEnvSecretName = 100

// reservedEnvPrefixes are variable families the platform or the runtime sets.
// An owner secret under one of them would either be refused by the runtime at
// launch or silently shadow a value the platform relies on.
var reservedEnvPrefixes = []string{"DATABASE_", "APPHUB_", "AWS_", "ECS_"}

// reservedEnvNames are single variables the platform sets.
var reservedEnvNames = []string{"PORT", EnvTableName, EnvBucketName, EnvBucketURI}

// ValidateEnvSecretName reports why name cannot be an environment secret, or
// nil. It is exported so the control plane can refuse a name at the request
// rather than on the worker, minutes later.
func ValidateEnvSecretName(name string) error {
	if len(name) == 0 || len(name) > maxEnvSecretName || !envNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q is not an environment variable name: use A-Z, 0-9 and "+
			"underscore, starting with a letter or underscore, at most %d characters",
			ErrInvalidApplication, name, maxEnvSecretName)
	}
	for _, reserved := range reservedEnvNames {
		if name == reserved {
			return fmt.Errorf("%w: %s is set by the platform", ErrInvalidApplication, name)
		}
	}
	for _, prefix := range reservedEnvPrefixes {
		if strings.HasPrefix(name, prefix) {
			return fmt.Errorf("%w: names starting with %s are reserved for the platform",
				ErrInvalidApplication, prefix)
		}
	}
	return nil
}

// SecretValueSource supplies the values an owner set on this deploy.
//
// A [Store] implements it when it carries any. It is a separate, optional
// interface rather than a method on Store for two reasons: most stores never
// carry a value, and a value must never pass through [Application], which is
// persisted. The returned map is keyed by variable name, holds only the names
// being set on this deploy, and every key must also be in
// [Application.EnvSecrets].
type SecretValueSource interface {
	EnvSecretValues(ctx context.Context, applicationID string) (map[string]compute.SecretValue, error)
}

// reconcileEnvSecrets writes every value set on this deploy, deletes every
// stored environment secret the application no longer lists, and refuses a
// listed name that has neither a stored entry nor a new value -- binding it
// would fail at launch, after the image, identity and data were all converged.
func (m *Module) reconcileEnvSecrets(ctx context.Context, app *Application, binder *secretBinder) error {
	values, err := m.envSecretValues(ctx, app)
	if err != nil {
		return err
	}
	if (len(app.EnvSecrets) > 0 || len(values) > 0) && binder.store == nil {
		return fmt.Errorf("%w: environment secrets need a secret store and provider %q has none",
			compute.ErrUnsupported, m.provider.Name())
	}
	wanted := make(map[string]bool, len(app.EnvSecrets))
	for _, name := range app.EnvSecrets {
		if err := ValidateEnvSecretName(name); err != nil {
			return err
		}
		wanted[name] = true
	}
	for _, name := range sortedKeys(values) {
		if !wanted[name] {
			return fmt.Errorf("%w: a value was supplied for %s, which the application does not list",
				ErrInvalidApplication, name)
		}
		if _, err := binder.put(ctx, envSecretPrefix+name, values[name], secretLabels(app)); err != nil {
			app.Artifacts.Secrets = binder.refs()
			return err
		}
	}
	for _, key := range sortedKeys(binder.issued) {
		name, ok := strings.CutPrefix(key, envSecretPrefix)
		if !ok || wanted[name] {
			continue
		}
		if err := binder.store.Delete(ctx, binder.issued[key]); err != nil {
			app.Artifacts.Secrets = binder.refs()
			return fmt.Errorf("deleting environment secret %s: %w", name, err)
		}
		delete(binder.issued, key)
	}
	app.Artifacts.Secrets = binder.refs()
	for _, name := range app.EnvSecrets {
		if _, ok := binder.issued[envSecretPrefix+name]; !ok {
			return fmt.Errorf("%w: secret %s has no stored value; set it again", ErrInvalidApplication, name)
		}
	}
	return nil
}

func (m *Module) envSecretValues(ctx context.Context, app *Application) (map[string]compute.SecretValue, error) {
	source, ok := m.store.(SecretValueSource)
	if !ok {
		return nil, nil
	}
	values, err := source.EnvSecretValues(ctx, app.ID)
	if err != nil {
		return nil, fmt.Errorf("reading secret values for this deploy: %w", err)
	}
	return values, nil
}

// envSecretBindings binds every listed secret to its variable, unpinned: the
// owner replaces a value by deploying, and the deploy that replaced it wants
// the new revision.
func envSecretBindings(app *Application, binder *secretBinder) ([]compute.SecretBinding, error) {
	bindings := make([]compute.SecretBinding, 0, len(app.EnvSecrets))
	for _, name := range app.EnvSecrets {
		binding, err := binder.bindName(name, envSecretPrefix+name, "")
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
