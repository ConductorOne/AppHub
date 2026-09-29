// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules_test

import (
	"testing"

	"github.com/conductorone/apphub/modules"
)

func TestValidateDeclaredParams(t *testing.T) {
	t.Parallel()

	declared := &modules.JSONSchema{
		Type: "object",
		Properties: map[string]modules.JSONSchemaProperty{
			"repo":   {Type: "string"},
			"branch": {Type: "string"},
		},
		Required: []string{"repo"},
	}

	tests := []struct {
		name    string
		schema  *modules.JSONSchema
		params  map[string]any
		wantErr string
	}{
		{
			name:   "all declared",
			schema: declared,
			params: map[string]any{"repo": "r", "branch": "b"},
		},
		{
			name:   "subset of declared",
			schema: declared,
			params: map[string]any{"repo": "r"},
		},
		{
			name:   "no params at all",
			schema: declared,
			params: map[string]any{},
		},
		{
			name:   "nil params",
			schema: declared,
			params: nil,
		},
		{
			// The case the check exists for: a key Execute happens to read but
			// never published is not caller-settable.
			name:    "one undeclared key",
			schema:  declared,
			params:  map[string]any{"repo": "r", "destinationBucket": "caller-chosen"},
			wantErr: "undeclared parameter(s) not present in the module schema: destinationBucket",
		},
		{
			// Named and sorted, so the message is deterministic across runs and
			// tells the caller everything to remove in one round trip.
			name:    "several undeclared keys are reported sorted",
			schema:  declared,
			params:  map[string]any{"zeta": 1, "alpha": 2, "mu": 3},
			wantErr: "undeclared parameter(s) not present in the module schema: alpha, mu, zeta",
		},
		{
			// Fail closed: a module that forgot to publish a schema is unusable
			// rather than unguarded.
			name:    "nil schema rejects every key",
			schema:  nil,
			params:  map[string]any{"repo": "r"},
			wantErr: "undeclared parameter(s) not present in the module schema: repo",
		},
		{
			name:   "nil schema with no params is vacuously fine",
			schema: nil,
			params: nil,
		},
		{
			// A schema object with no Properties declares nothing, the same as a
			// nil schema does.
			name:    "schema with nil properties rejects every key",
			schema:  &modules.JSONSchema{Type: "object"},
			params:  map[string]any{"repo": "r"},
			wantErr: "undeclared parameter(s) not present in the module schema: repo",
		},
		{
			// Required is not consulted here: this check is about keys that are
			// present and undeclared, not keys that are declared and absent.
			// A module's own Validate covers the latter.
			name:   "missing required key is not this check's concern",
			schema: declared,
			params: map[string]any{"branch": "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := modules.ValidateDeclaredParams(tt.schema, tt.params)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("no error; want %q", tt.wantErr)
			case tt.wantErr != "" && err.Error() != tt.wantErr:
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestValidateDeclaredParamsMessageIsStable runs the same undeclared set
// repeatedly. Go randomises map iteration order, so an unsorted implementation
// fails this in a handful of iterations rather than once in a blue moon on
// somebody else's machine.
func TestValidateDeclaredParamsMessageIsStable(t *testing.T) {
	t.Parallel()

	params := map[string]any{"d": 1, "a": 2, "c": 3, "b": 4}
	const want = "undeclared parameter(s) not present in the module schema: a, b, c, d"

	for i := 0; i < 100; i++ {
		err := modules.ValidateDeclaredParams(&modules.JSONSchema{Type: "object"}, params)
		if err == nil {
			t.Fatal("no error; want a rejection")
		}
		if err.Error() != want {
			t.Fatalf("iteration %d: error = %q, want %q", i, err.Error(), want)
		}
	}
}
