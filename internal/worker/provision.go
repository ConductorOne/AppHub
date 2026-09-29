// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// DeploymentProvisioner is an optional external directory integration. Each
// operation must be idempotent: deployments and teardowns may be retried after
// ambiguous external responses without duplicating or orphaning applications.
type DeploymentProvisioner interface {
	ProvisionApplication(ctx context.Context, appID, name, url string) error
	ProvisionGoLink(ctx context.Context, appID, alias, url string) error
	DeleteApplication(ctx context.Context, appID string) error
}

// WithDeploymentProvisioner enables C1 provisioning for workspace flags that
// opt in. An unconfigured provisioner is never treated as successful.
func WithDeploymentProvisioner(provisioner DeploymentProvisioner) Option {
	return func(d *Dispatcher) { d.provisioner = provisioner }
}

func (d *Dispatcher) provisionDeployment(ctx context.Context, app cp.ApplicationRecord, target cp.TargetPolicy) error {
	appEnabled, err := d.provisionFlag(ctx, cp.FeatureProvisionAppCatalog)
	if err != nil {
		return fmt.Errorf("read feature flag %s: %w", cp.FeatureProvisionAppCatalog, err)
	}
	linkEnabled, err := d.provisionFlag(ctx, cp.FeatureProvisionShortLink)
	if err != nil {
		return fmt.Errorf("read feature flag %s: %w", cp.FeatureProvisionShortLink, err)
	}
	if !appEnabled && !linkEnabled {
		return nil
	}
	if d.provisioner == nil {
		return errors.New("external provisioning is enabled but its credentials are not configured")
	}
	url := ""
	if len(app.Application.Routes) > 0 {
		route := app.Application.Routes[0]
		domain := target.DeployConfig.RouteDomain
		if route.Internal {
			domain = target.DeployConfig.InternalRouteDomain
		}
		if route.Hostname != "" && domain != "" {
			url = "https://" + strings.ToLower(strings.TrimSpace(route.Hostname)) + "." + strings.ToLower(strings.TrimSpace(domain))
		}
	}
	if appEnabled {
		if err := d.provisioner.ProvisionApplication(ctx, app.ID, app.Input.Name, url); err != nil {
			return fmt.Errorf("provision external application: %w", err)
		}
	}
	if linkEnabled {
		if url == "" {
			return errors.New("a deployed application URL is required to create a GoLink")
		}
		if err := d.provisioner.ProvisionGoLink(ctx, app.ID, app.Input.Name, url); err != nil {
			return fmt.Errorf("provision GoLink: %w", err)
		}
	}
	return nil
}

func (d *Dispatcher) provisionFlag(ctx context.Context, key string) (bool, error) {
	row, err := d.repo.Read(ctx, cp.RecordID{Kind: cp.FeatureFlagKind, ID: key})
	if errors.Is(err, cp.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	flag, err := cp.Decode[cp.FeatureFlagRecord](row)
	if err != nil {
		return false, err
	}
	return flag.Mode == cp.FeatureFlagOn, nil
}
