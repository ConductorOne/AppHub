// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package worker

import (
	"context"
	"errors"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func TestOnlySuccessfulReconciliationReleasesObsoleteHostnames(t *testing.T) {
	for _, state := range []cp.DeploymentState{cp.Succeeded, cp.Failed, cp.Interrupted} {
		t.Run(string(state), func(t *testing.T) {
			f := newWorkerFixture(t)
			row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID})
			if err != nil {
				t.Fatal(err)
			}
			app := f.application(t)
			app.ReservedHostnames = []string{"previous", "current"}
			app.Input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "current"}
			update, err := recordMutation(row, app)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.repo.Commit(context.Background(), []cp.Mutation{update}); err != nil {
				t.Fatal(err)
			}
			for _, hostname := range app.ReservedHostnames {
				putWorkerRecord(t, f.repo, cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: hostname}, cp.HostnameReservation{TargetID: app.TargetID, Hostname: hostname, ApplicationID: app.ID})
			}
			operation, _ := f.claim(t)
			if err := operation.finish(state, "", ""); err != nil {
				t.Fatal(err)
			}
			_, oldErr := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: "previous"})
			if state == cp.Succeeded {
				if !errors.Is(oldErr, cp.ErrNotFound) {
					t.Fatalf("confirmed obsolete route remains reserved: %v", oldErr)
				}
			} else if oldErr != nil {
				t.Fatalf("uncertain/live route was released: %v", oldErr)
			}
			current := readWorkerRecord[cp.HostnameReservation](t, f.repo, cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: "current"})
			if current.ApplicationID != app.ID {
				t.Fatal("current route lost ownership")
			}
			finished := f.application(t)
			if state == cp.Interrupted && finished.ActiveDeploymentID == "" {
				t.Fatal("interruption released execution fence")
			}
		})
	}
}
