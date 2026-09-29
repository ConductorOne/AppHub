// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package ext_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// The lookup helpers are the entire mechanism by which "this substrate cannot
// do this" becomes a fact the caller must handle. Two properties matter and are
// tested here: a provider that implements a port is found, and one that does
// not produces an error that the caller's existing ErrUnsupported branch
// already catches. If the second ever regressed to a nil interface, the failure
// would move from a deploy-time message to a panic in production.

// plainStore implements only the portable object-store port.
type plainStore struct{ compute.ObjectStore }

// richStore additionally implements the non-portable ports, as an AWS provider
// would.
type richStore struct{ plainStore }

func (richStore) EnsureTableBucket(context.Context, compute.BucketSpec) (*compute.Bucket, error) {
	return nil, nil
}
func (richStore) DeleteTableBucket(context.Context, compute.Ref) error { return nil }
func (richStore) EnsureVectorBucket(context.Context, compute.BucketSpec) (*compute.Bucket, error) {
	return nil, nil
}
func (richStore) DeleteVectorBucket(context.Context, compute.Ref) error { return nil }
func (richStore) Grant(context.Context, compute.Ref, compute.Ref, compute.AccessLevel) error {
	return nil
}
func (richStore) Revoke(context.Context, compute.Ref, compute.Ref) error { return nil }
func (richStore) DescribeGrant(context.Context, compute.Ref, compute.Ref) (*compute.GrantInfo, error) {
	return nil, nil
}
func (richStore) GrantExternal(context.Context, compute.Ref, ext.ExternalPrincipal, compute.AccessLevel) error {
	return nil
}
func (richStore) RevokeExternal(context.Context, compute.Ref, ext.ExternalPrincipal) error {
	return nil
}
func (richStore) ExternalGrants(context.Context, compute.Ref) ([]ext.ExternalGrant, error) {
	return nil, nil
}

// TestExternalPrincipalConstraintsAreNotTypedAsSecrets pins the naming
// decision. The field used to be called SharedSecrets while holding plain
// strings, which claimed a property the values do not have: an AWS external ID
// is documented as not-secret, and its job is to prevent a confused deputy
// rather than to authenticate. A name that says "secret" over an unprotected
// string is the worst of both — it misleads an auditor and protects nothing.
func TestExternalPrincipalConstraintsAreNotTypedAsSecrets(t *testing.T) {
	t.Parallel()

	p := ext.ExternalPrincipal{
		ID:          "external-principal-id",
		Constraints: []string{"agreed-correlation-value"},
	}
	if len(p.Constraints) != 1 {
		t.Fatal("Constraints did not round-trip")
	}

	rt := reflect.TypeOf(ext.ExternalPrincipal{})
	for i := range rt.NumField() {
		if strings.Contains(strings.ToLower(rt.Field(i).Name), "secret") {
			t.Errorf("ExternalPrincipal.%s names itself a secret but holds %s; either type it as "+
				"secret material or name it for what it is", rt.Field(i).Name, rt.Field(i).Type)
		}
	}
}

func TestLookupsFindImplementedPorts(t *testing.T) {
	t.Parallel()

	store := richStore{}

	if _, err := ext.TableBuckets("aws", store); err != nil {
		t.Errorf("TableBuckets did not find an implemented port: %v", err)
	}
	if _, err := ext.VectorBuckets("aws", store); err != nil {
		t.Errorf("VectorBuckets did not find an implemented port: %v", err)
	}
	if _, err := ext.ExternalAccess("aws", store); err != nil {
		t.Errorf("ExternalAccess did not find an implemented port: %v", err)
	}
}

func TestLookupsRefuseUnimplementedPorts(t *testing.T) {
	t.Parallel()

	store := plainStore{}

	lookups := map[string]func(string, compute.ObjectStore) error{
		"ext.TableBucketProvisioner": func(n string, s compute.ObjectStore) error {
			_, err := ext.TableBuckets(n, s)
			return err
		},
		"ext.VectorBucketProvisioner": func(n string, s compute.ObjectStore) error {
			_, err := ext.VectorBuckets(n, s)
			return err
		},
		"ext.ExternalAccessGranter": func(n string, s compute.ObjectStore) error {
			_, err := ext.ExternalAccess(n, s)
			return err
		},
	}

	for port, lookup := range lookups {
		t.Run(port, func(t *testing.T) {
			t.Parallel()

			err := lookup("kubernetes", store)
			if err == nil {
				t.Fatal("lookup succeeded against a provider that does not implement the port")
			}
			// The whole design rests on this: a caller that already handles
			// ErrUnsupported handles ext refusals too, with no second case.
			if !errors.Is(err, compute.ErrUnsupported) {
				t.Errorf("refusal does not match compute.ErrUnsupported: %v", err)
			}
			var target *ext.ErrNotImplemented
			if !errors.As(err, &target) {
				t.Fatalf("refusal is not an *ext.ErrNotImplemented: %v", err)
			}
			if target.Provider != "kubernetes" || target.Port != port {
				t.Errorf("refusal lost its detail: %#v", target)
			}
			if msg := err.Error(); !strings.Contains(msg, "kubernetes") || !strings.Contains(msg, port) {
				t.Errorf("message %q does not name both the provider and the port", msg)
			}
		})
	}
}
