// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"encoding/json"
	"strings"
	"testing"
)

// CreateLogGroup is authorized on the log group ARN. A resource that only
// names the streams under the group (the ":*" suffix) does not match that
// call, and the agent then never creates the group.
func TestLogWritePolicySeparatesGroupCreateFromStreamWrite(t *testing.T) {
	t.Parallel()

	p := &Provider{cfg: Config{Container: &ContainerConfig{LogGroupPrefix: "/apphub/dev/apps/"}}}
	raw := p.logWritePolicy("svc", PlacementConfig{Region: "us-west-2"})
	if raw == "" {
		t.Fatal("log write policy is empty")
	}
	var doc policyDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("policy is not JSON: %v", err)
	}
	group := "arn:aws:logs:us-west-2:*:log-group:/apphub/dev/apps/svc"
	var create, write bool
	for _, st := range doc.Statement {
		resources := statementResources(t, st.Resource)
		switch st.Sid {
		case "CreateThisServicesLogGroup":
			create = true
			if !stringIn(st.Action, "logs:CreateLogGroup") || !stringIn(resources, group) {
				t.Errorf("create statement = actions %v resources %v", st.Action, resources)
			}
			for _, r := range resources {
				if strings.HasSuffix(r, ":*") {
					t.Errorf("CreateLogGroup resource %q has a stream suffix", r)
				}
			}
		case "WriteThisServicesLogs":
			write = true
			if !stringIn(resources, group+":*") {
				t.Errorf("stream resource = %v, want %s", resources, group+":*")
			}
			if stringIn(st.Action, "logs:CreateLogGroup") {
				t.Error("stream statement also grants CreateLogGroup")
			}
		}
	}
	if !create || !write {
		t.Fatalf("policy statements = %+v", doc.Statement)
	}
}

func statementResources(t *testing.T, resource any) []string {
	t.Helper()
	switch v := resource.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				t.Fatalf("resource entry %T", e)
			}
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("resource type %T", resource)
		return nil
	}
}

func stringIn(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
