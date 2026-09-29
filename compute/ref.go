// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"fmt"
	"strings"
)

// Kind classifies what a [Ref] points at. It exists so that a Ref read back out
// of persistence can be checked against the method it is about to be passed to,
// turning a wiring mistake into an error instead of a confusing provider-side
// failure.
type Kind string

// The resource kinds a provider can issue a [Ref] for.
const (
	KindImageRepository  Kind = "image-repository"
	KindService          Kind = "service"
	KindScheduledJob     Kind = "scheduled-job"
	KindFunction         Kind = "function"
	KindFunctionEndpoint Kind = "function-endpoint"
	KindBucket           Kind = "bucket"
	KindRelational       Kind = "relational-database"
	KindKeyValueTable    Kind = "key-value-table"
	KindSecret           Kind = "secret"
	KindWorkloadIdentity Kind = "workload-identity"
)

// Ref is an opaque, provider-issued handle to a provisioned resource.
//
// A Ref is the only thing a caller persists in order to find a resource again
// on the next deploy, on a teardown, or from a different process. Two rules
// make that safe:
//
//   - Callers must never parse, construct, or pattern-match ID. It is whatever
//     the provider needs it to be — an ARN, a namespaced name, a UUID — and its
//     format is not part of any contract. The source system stored bare ARNs and
//     then reconstructed them by string template in a dozen places
//     (bucket.go:194-215, container.go:1530-1537); that is exactly the coupling
//     a Ref exists to prevent.
//   - Provider records which implementation issued the Ref. A provider handed a
//     Ref it did not issue must return [ErrForeignRef]. Without this field, a
//     platform reconfigured from AWS to Kubernetes would hand ARNs to a
//     Kubernetes client and get an unpredictable failure at an unpredictable
//     depth.
//
// Ref is comparable, so it can be used as a map key.
type Ref struct {
	// Provider is the [Provider.Name] of the implementation that issued this
	// Ref.
	Provider string
	// Kind is what the Ref points at.
	Kind Kind
	// ID is provider-internal and opaque to every caller.
	ID string
}

// IsZero reports whether r is the zero Ref, meaning "no resource". Callers use
// it to distinguish "never provisioned" from "provisioned and since deleted",
// which the source system conflated by storing empty strings.
func (r Ref) IsZero() bool {
	return r.Provider == "" && r.Kind == "" && r.ID == ""
}

// String renders a Ref as a single line for persistence and logging. The format
// is "provider:kind:id"; ID may itself contain colons, and [ParseRef] accounts
// for that by splitting only twice.
//
// This is the one exception to Ref opacity, and it is one-way for the caller:
// producing the string is supported, interpreting anything inside it is not.
func (r Ref) String() string {
	return r.Provider + ":" + string(r.Kind) + ":" + r.ID
}

// ParseRef is the inverse of [Ref.String], for reading a Ref back out of
// storage.
func ParseRef(s string) (Ref, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Ref{}, fmt.Errorf("compute: %q is not a resource reference", s)
	}
	return Ref{Provider: parts[0], Kind: Kind(parts[1]), ID: parts[2]}, nil
}
