// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

func TestExtensionsInstallWithTemporaryAdminIngress(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "SQL failure"}[fail], func(t *testing.T) {
			p := newTestProvider(t)
			app := testApplication()
			app.Routes = nil
			app.Bucket = Bucket{}
			app.Secrets = nil
			app.Database.Extensions = []string{"vector", "uuid-ossp"}
			store := newMemStore(app)
			cfg := testConfig()
			cfg.PostgresRootCertPath = "/operator/rds-ca.pem"
			m, _, _ := newTestModule(t, p, store, cfg)
			calls := 0
			m.installExtensions = func(ctx context.Context, endpoint compute.SQLEndpoint, user string, password compute.SecretValue, cert string, names []string) error {
				calls++
				if endpoint.Host == "" || endpoint.Port != 5432 || endpoint.DatabaseName != app.Database.DatabaseName || user != app.Database.AdminUsername || password.IsZero() || cert != cfg.PostgresRootCertPath || len(names) != 2 {
					t.Errorf("installer did not receive the ready database, admin credential, CA path and requested extensions: endpoint=%+v user=%q cert=%q names=%v", endpoint, user, cert, names)
				}
				rel, err := p.Relational()
				if err != nil {
					return err
				}
				status, err := rel.DescribeRelational(ctx, store.saved(app.ID).Artifacts.Relational)
				if err != nil {
					return err
				}
				if len(status.Spec.Ingress) != 1 || status.Spec.Ingress[0].From.Kind != compute.PeerControlPlane {
					t.Errorf("SQL ran without temporary control-plane ingress: %v", status.Spec.Ingress)
				}
				if fail {
					return errors.New("SQL extension unavailable")
				}
				return nil
			}
			_, err := m.Execute(context.Background(), "u1", map[string]any{"applicationId": app.ID})
			if (err != nil) != fail || (fail && !strings.Contains(err.Error(), "SQL extension unavailable")) {
				t.Fatalf("deployment error = %v; SQL failure = %t", err, fail)
			}
			if calls != 1 {
				t.Fatalf("installer ran %d times, want once", calls)
			}
			saved := store.saved(app.ID)
			rel, err := p.Relational()
			if err != nil {
				t.Fatal(err)
			}
			status, err := rel.DescribeRelational(context.Background(), saved.Artifacts.Relational)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range status.Spec.Ingress {
				if rule.From.Kind == compute.PeerControlPlane {
					t.Errorf("temporary admin ingress survived deployment: %v", status.Spec.Ingress)
				}
			}
			if fail && (saved.Status != StatusFailed || saved.FailedStep != "database-extensions") {
				t.Errorf("extension error marked deployment status %q at step %q", saved.Status, saved.FailedStep)
			}
		})
	}
}

func TestExtensionsRequireInstallerBeforeCreatingResources(t *testing.T) {
	p := newTestProvider(t)
	app := testApplication()
	app.Database.Extensions = []string{"vector"}
	store := newMemStore(app)
	cfg := testConfig()
	cfg.PostgresRootCertPath = "/operator/rds-ca.pem"
	m, _, _ := newTestModule(t, p, store, cfg)

	_, err := m.Execute(context.Background(), "u1", map[string]any{"applicationId": app.ID})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unwired extension installer error = %v, want ErrNotConfigured", err)
	}
	if store.saves != 0 {
		t.Errorf("unwired installer wrote %d application checkpoints", store.saves)
	}
	if resources := rendered(t, p); len(resources) != 0 {
		t.Errorf("unwired installer provisioned resources: %v", resources)
	}
}
