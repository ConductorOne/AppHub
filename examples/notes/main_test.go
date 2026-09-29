// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestLoadSettings(t *testing.T) {
	tests := []struct {
		name, table, endpoint, devEmail string
		wantErr                         string
	}{
		{name: "deployed", table: "notes-table"},
		{name: "local", table: "notes", endpoint: "http://localhost:8001", devEmail: "dev@example.com"},
		{name: "no table", wantErr: "TABLE_NAME is not set"},
		{
			name: "dev email outside local", table: "notes-table", devEmail: "dev@example.com",
			wantErr: "DEV_USER_EMAIL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TABLE_NAME", tt.table)
			t.Setenv("LOCAL_DYNAMO_ENDPOINT", tt.endpoint)
			t.Setenv("DEV_USER_EMAIL", tt.devEmail)
			s, err := loadSettings()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want one mentioning %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || s.table != tt.table || s.devEmail != tt.devEmail {
				t.Fatalf("settings = %+v, %v", s, err)
			}
		})
	}
}
