// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/conductorone/apphub/credentials"
)

// AnnotationKey is a declared, non-secret annotation key.
//
// It is a distinct type so that a key cannot be conjured from an arbitrary
// string at a call site: the keys a provider may persist are constants somewhere,
// which means adding one is a diff a reviewer sees.
type AnnotationKey string

// Well-known annotation keys. A provider still has to declare the ones it uses --
// these exist so that two providers naming the same concept spell it the same way.
const (
	AnnotationRegion         AnnotationKey = "region"
	AnnotationInstallationID AnnotationKey = "installation_id"
	AnnotationDeviceID       AnnotationKey = "device_id"
	AnnotationAccountAlias   AnnotationKey = "account_alias"
	AnnotationEntitlement    AnnotationKey = "entitlement"
)

// Annotations is the non-secret provider context persisted on a Record.
type Annotations map[AnnotationKey]string

// Errors returned when annotations or a schema are rejected.
var (
	// ErrUndeclaredAnnotation means a key was not in the provider's schema. This is
	// the enforcement: what may be persisted is an allowlist, and a provider with
	// no schema may persist nothing.
	ErrUndeclaredAnnotation = errors.New("annotation key is not declared by this provider")

	// ErrSecretAnnotation means a schema tried to declare a key whose name says it
	// holds credential material. It is a lint on the schema, applied once when the
	// schema is registered, not a runtime filter on data.
	ErrSecretAnnotation = errors.New("annotation key names credential material")

	// ErrSchemaAlreadyRegistered means a provider registered a schema twice.
	ErrSchemaAlreadyRegistered = errors.New("annotation schema already registered for this provider")
)

// Annotation limits. Small on purpose: this is context on an audit record, not a
// place to put a payload.
const (
	MaxAnnotationKeys      = 16
	MaxAnnotationKeyLen    = 64
	MaxAnnotationValueLen  = 512
	maxSchemaKeysPerSchema = MaxAnnotationKeys
)

// AnnotationRegistry decides which annotation keys each provider may persist.
//
// The previous design was a denylist: any key was accepted unless its name
// contained something secret-looking. A review fixture defeated it in one line by
// storing an admin key under "value", which is the failure mode every denylist
// has -- it enumerates what is forbidden, and the interesting cases are the ones
// nobody enumerated.
//
// This is the inversion. A provider declares the keys it persists; anything else
// is refused, and a provider that declared nothing persists nothing. The denylist
// survives as a lint on schema registration, where it belongs: catching a
// developer about to declare "api_key" as a legitimate annotation, in a diff,
// once, rather than trying to police runtime data forever.
//
// What this still cannot do is inspect values. A provider that declares "region"
// and then stores an access key in it defeats this, exactly as it would defeat
// any key-based scheme. The property established is narrower and real: every key
// persisted on a record was named by a human in a reviewed change.
type AnnotationRegistry struct {
	mu      sync.RWMutex
	schemas map[string]map[AnnotationKey]struct{}
}

// NewAnnotationRegistry returns an empty registry. Empty means no provider may
// persist any annotation, which is the correct starting point.
func NewAnnotationRegistry() *AnnotationRegistry {
	return &AnnotationRegistry{schemas: make(map[string]map[AnnotationKey]struct{})}
}

// Register declares the annotation keys a provider may persist.
//
// It rejects a duplicate registration rather than replacing one, for the same
// reason ProviderRegistry.Register does: two declarations for one provider mean
// two pieces of code disagree about what is allowed, and letting the last one win
// makes the answer depend on wiring order.
func (r *AnnotationRegistry) Register(providerID string, keys ...AnnotationKey) error {
	if providerID == "" {
		return errors.New("provider ID is required")
	}
	if len(keys) > maxSchemaKeysPerSchema {
		return fmt.Errorf("schema for provider %s declares %d keys (max %d)",
			credentials.NewForeign(providerID), len(keys), maxSchemaKeysPerSchema)
	}

	set := make(map[AnnotationKey]struct{}, len(keys))
	for _, k := range keys {
		if err := checkKeyName(k); err != nil {
			return fmt.Errorf("schema for provider %s: %w", credentials.NewForeign(providerID), err)
		}
		set[k] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.schemas[providerID]; exists {
		return fmt.Errorf("%w: %s", ErrSchemaAlreadyRegistered, credentials.NewForeign(providerID))
	}
	r.schemas[providerID] = set
	return nil
}

// Validate checks annotations against the provider's declared schema.
//
// Records implementations must call this before persisting. Failing the write is
// correct: dropping the offending key and carrying on would mean the caller
// believes it stored something it did not.
func (r *AnnotationRegistry) Validate(providerID string, a Annotations) error {
	if len(a) == 0 {
		return nil
	}
	if len(a) > MaxAnnotationKeys {
		return fmt.Errorf("too many annotations: %d (max %d)", len(a), MaxAnnotationKeys)
	}

	r.mu.RLock()
	schema, ok := r.schemas[providerID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: provider %s declared no annotation schema",
			ErrUndeclaredAnnotation, credentials.NewForeign(providerID))
	}

	for k, v := range a {
		if _, allowed := schema[k]; !allowed {
			return fmt.Errorf("%w: provider %s, key %s",
				ErrUndeclaredAnnotation, credentials.NewForeign(providerID), credentials.NewForeign(string(k)))
		}
		if len(v) > MaxAnnotationValueLen {
			return fmt.Errorf("annotation %s value too long: %d bytes (max %d)",
				credentials.NewForeign(string(k)), len(v), MaxAnnotationValueLen)
		}
	}
	return nil
}

// Declared returns the keys a provider may persist, for diagnostics.
func (r *AnnotationRegistry) Declared(providerID string) []AnnotationKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AnnotationKey, 0, len(r.schemas[providerID]))
	for k := range r.schemas[providerID] {
		out = append(out, k)
	}
	return out
}

// secretishKeyNames is the schema-registration lint described on
// AnnotationRegistry. It is not a security boundary and is not applied to data.
var secretishKeyNames = []string{
	"secret", "password", "passwd", "token", "api_key", "apikey",
	"private_key", "privatekey", "credential", "session", "signature", "bearer",
}

func checkKeyName(k AnnotationKey) error {
	if k == "" {
		return errors.New("empty annotation key")
	}
	if len(k) > MaxAnnotationKeyLen {
		return fmt.Errorf("annotation key %s too long: %d bytes (max %d)",
			credentials.NewForeign(string(k)), len(k), MaxAnnotationKeyLen)
	}
	lower := strings.ToLower(string(k))
	for _, banned := range secretishKeyNames {
		if strings.Contains(lower, banned) {
			return fmt.Errorf("annotation key %s: %w", credentials.NewForeign(string(k)), ErrSecretAnnotation)
		}
	}
	return nil
}
