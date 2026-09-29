// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command devseed fills a local AppHub state table with demo users and
// applications that look deployed: deployment history, artifacts, secrets,
// owners and traffic. Nothing is provisioned; every record describes
// infrastructure that does not exist. It is for local screenshots and UI
// review only and refuses to write anywhere but an explicit local endpoint.
//
// Seeding is idempotent: a user or application that already exists is left
// untouched. -remove deletes every demo record again; audit entries remain.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/store"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "devseed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("devseed", flag.ContinueOnError)
	configPath := flags.String("config", "", "serve configuration (.local/server.yaml)")
	ownerEmail := flags.String("owner-email", "", "email of a signed-in user who should own some demo applications")
	repositories := flags.Bool("repositories", false, "print the demo repositories as source.repositories YAML and exit")
	remove := flags.Bool("remove", false, "delete every demo user and application instead of seeding")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *repositories {
		for _, app := range demoApps {
			if _, err := fmt.Fprintf(out, "    - url: %s\n      auth: public\n", repoURL(app)); err != nil {
				return err
			}
		}
		return nil
	}
	if *configPath == "" || (*ownerEmail == "" && !*remove) {
		return errors.New("-config is required, and -owner-email unless -remove is set")
	}

	cfg, err := serverconfig.Load(*configPath, serverconfig.ModeServe)
	if err != nil {
		return fmt.Errorf("load %s: %w", *configPath, err)
	}
	if err := requireLocalEndpoint(cfg.Store.Endpoint); err != nil {
		return err
	}
	client, err := store.New(ctx, store.Config{Region: cfg.Store.Region, TableName: cfg.Store.TableName, AuditTableName: cfg.Store.AuditTableName, Endpoint: cfg.Store.Endpoint})
	if err != nil {
		return err
	}
	repo, err := store.NewControlPlaneRecords(client)
	if err != nil {
		return err
	}
	if err := repo.Ready(ctx); err != nil {
		return fmt.Errorf("local table is not ready (run make infra-up): %w", err)
	}

	s := &seeder{repo: repo, now: time.Now().UTC()}
	if *remove {
		return s.remove(ctx, out)
	}
	if s.target, err = targetPolicy(cfg); err != nil {
		return err
	}
	return s.seed(ctx, *ownerEmail, out)
}

// requireLocalEndpoint keeps demo records out of any real table.
func requireLocalEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || endpoint == "" {
		return errors.New("store.endpoint must name a local DynamoDB endpoint")
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return nil
	}
	return fmt.Errorf("store.endpoint %q is not loopback; refusing to seed demo data", endpoint)
}

// targetPolicy mirrors cmd/apphub's targetPolicies for the one local target,
// without the AWS configuration hash nothing here checks.
func targetPolicy(cfg serverconfig.Config) (controlplane.TargetPolicy, error) {
	if len(cfg.Targets) != 1 {
		return controlplane.TargetPolicy{}, fmt.Errorf("expected exactly one target, found %d", len(cfg.Targets))
	}
	for id, t := range cfg.Targets {
		p := controlplane.TargetPolicy{ID: id, Label: t.Label, DeployConfig: t.DeployConfig(), MaxReplicas: t.Policy.MaxReplicas, MaxRelationalCapacityUnits: t.Policy.MaxRelationalCapacityUnits, PublicExposure: t.Policy.PublicExposure}
		for _, repo := range cfg.Source.Repositories {
			p.Repositories = append(p.Repositories, repo.URL)
		}
		for _, size := range t.Policy.ResourceSizes {
			p.ResourceSizes = append(p.ResourceSizes, controlplane.ResourceInput{CPU: size.CPU, Memory: size.Memory})
		}
		for _, mode := range t.Policy.ExecutionModes {
			p.ExecutionModes = append(p.ExecutionModes, string(mode))
		}
		return p, requireDemoPolicy(p)
	}
	return controlplane.TargetPolicy{}, errors.New("no target configured")
}

// requireDemoPolicy names every policy setting the catalog needs, so a
// missing one is one clear message rather than 47 validation failures.
func requireDemoPolicy(p controlplane.TargetPolicy) error {
	var missing []string
	if !slices.Contains(p.ExecutionModes, "scheduled") {
		missing = append(missing, "policy.executionModes must include scheduled")
	}
	if !p.PublicExposure || p.DeployConfig.RouteDomain == "" {
		missing = append(missing, "policy.publicExposure with deployConfig.routeDomain/routeCertificate")
	}
	if p.DeployConfig.InternalRouteDomain == "" {
		missing = append(missing, "deployConfig.internalRouteDomain/internalRouteCertificate")
	}
	if len(p.Repositories) > 0 {
		for _, app := range demoApps {
			if !slices.Contains(p.Repositories, repoURL(app)) {
				missing = append(missing, "source.repositories must list the demo repositories (see -repositories)")
				break
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("target %q cannot hold the demo catalog:\n  %s", p.ID, strings.Join(missing, "\n  "))
	}
	return nil
}

func repoURL(app demoApp) string { return "https://github.com/" + demoOrg + "/" + app.repo }
