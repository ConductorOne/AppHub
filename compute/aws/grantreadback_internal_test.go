// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// The level inverse, tested against the two things a real substrate does to a
// document between the write and the read.
//
// [MemoryIAM] returns exactly what it was given, so a test written only through
// the provider exercises neither: not the URL encoding IAM applies to every
// inline policy document, and not the re-serialisation a service is free to
// perform on JSON it stored. Both would turn every grant this provider ever wrote
// into an unreadable one, and neither is reachable from the in-memory substrate —
// which is precisely why they are tested here rather than left to it.

// TestTheLevelInverseReadsAURLEncodedDocument covers the encoding IAM applies.
//
// GetRolePolicy returns an inline policy document URL-encoded, and [sdkIAM] hands
// back what IAM gave it unaltered and says so in as many words: the decoding is
// the caller's. This is the caller.
func TestTheLevelInverseReadsAURLEncodedDocument(t *testing.T) {
	t.Parallel()

	rendered, err := keyValueAccessPolicy("arn:aws:dynamodb:us-east-1:1:table/t", compute.AccessRead)
	if err != nil {
		t.Fatalf("keyValueAccessPolicy(): %v", err)
	}
	render := func(l compute.AccessLevel) (string, error) {
		return keyValueAccessPolicy("arn:aws:dynamodb:us-east-1:1:table/t", l)
	}

	encoded := url.QueryEscape(rendered)
	if !strings.HasPrefix(encoded, "%7B") {
		t.Fatalf("the fixture is not URL-encoded, so it tests the plain path twice: %q", encoded)
	}
	level, err := levelFromStoredPolicy(encoded, render)
	if err != nil {
		t.Fatalf("levelFromStoredPolicy() over a URL-encoded document: %v. This is what IAM "+
			"returns from GetRolePolicy, so a failure here means every grant against real AWS "+
			"reads back as unrecognisable while the in-memory substrate stays green", err)
	}
	if level != compute.AccessRead {
		t.Errorf("a URL-encoded AccessRead document read back as %q", level)
	}
}

// TestTheLevelInverseComparesMeaningRatherThanBytes covers the re-serialisation a
// substrate is free to perform.
//
// Every rewrite below leaves the policy identical and a string comparison false:
// key order within a statement, whitespace, and a one-element list where IAM also
// accepts a scalar. The comparison goes through [samePolicyDocument], which
// already existed for the trust-policy convergence check and handles all three;
// this asserts that the grant path really is using it rather than comparing text.
func TestTheLevelInverseComparesMeaningRatherThanBytes(t *testing.T) {
	t.Parallel()

	const arn = "arn:aws:dynamodb:us-east-1:1:table/t"
	render := func(l compute.AccessLevel) (string, error) { return keyValueAccessPolicy(arn, l) }

	// Hand-written to be the AccessRead document with the keys reordered, spaces
	// added, and the Sid last. Written out rather than derived from the renderer,
	// because a fixture derived from the thing under test cannot disagree with it.
	reordered := `{
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Resource": ["` + arn + `/index/*", "` + arn + `"],
	      "Action": [
	        "dynamodb:Query", "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Scan"
	      ],
	      "Sid": "AppHubKeyValueAccess"
	    }
	  ],
	  "Version": "2012-10-17"
	}`
	level, err := levelFromStoredPolicy(reordered, render)
	if err != nil {
		t.Fatalf("levelFromStoredPolicy() over a re-serialised document: %v", err)
	}
	if level != compute.AccessRead {
		t.Errorf("a re-serialised AccessRead document read back as %q; the action and resource "+
			"lists were reordered and the whitespace changed, neither of which alters what the "+
			"policy permits", level)
	}
}

// TestTheLevelInverseRefusesRatherThanGuesses is the negative half, at the level
// of the function rather than the port.
//
// A document that is not one this provider would render for any level it defines
// has no honest answer, and the two dishonest ones fail in opposite directions.
// The refusal must also not be [compute.ErrNotFound]: something is standing
// there, and a caller told the pair has no grant will write a second one beside
// it.
func TestTheLevelInverseRefusesRatherThanGuesses(t *testing.T) {
	t.Parallel()

	const arn = "arn:aws:dynamodb:us-east-1:1:table/t"
	render := func(l compute.AccessLevel) (string, error) { return keyValueAccessPolicy(arn, l) }

	for _, tc := range []struct {
		name string
		doc  string
	}{
		{
			// Wider than any level: the escalation direction.
			name: "a wildcard nobody rendered",
			doc:  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:*"],"Resource":["*"]}]}`,
		},
		{
			// The read action set against a DIFFERENT table. Same shape, same
			// actions, wrong resource -- the case a comparison that only looked
			// at actions would report as a valid read grant.
			name: "the right actions on the wrong resource",
			doc: `{"Version":"2012-10-17","Statement":[{"Sid":"AppHubKeyValueAccess",` +
				`"Effect":"Allow","Action":["dynamodb:BatchGetItem","dynamodb:GetItem",` +
				`"dynamodb:Query","dynamodb:Scan"],"Resource":` +
				`["arn:aws:dynamodb:us-east-1:1:table/other",` +
				`"arn:aws:dynamodb:us-east-1:1:table/other/index/*"]}]}`,
		},
		{
			name: "not a policy document at all",
			doc:  "this is not JSON and not URL-encoded JSON either",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			level, err := levelFromStoredPolicy(tc.doc, render)
			if !errors.Is(err, compute.ErrFailed) {
				t.Errorf("levelFromStoredPolicy() = (%q, %v), want an error wrapping "+
					"compute.ErrFailed", level, err)
			}
			if errors.Is(err, compute.ErrNotFound) {
				t.Error("the refusal wraps compute.ErrNotFound, which says the pair has no grant. " +
					"A document is standing there, and a caller acting on 'no grant' grants again")
			}
			if level != "" {
				t.Errorf("a refused inverse still reported level %q", level)
			}
		})
	}
}
