// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"fmt"
	"sort"
	"strings"
)

// ValidateDeclaredParams rejects any key of params that schema does not declare.
//
// A module's Schema is its published contract, and a Validate that checks only
// the parameters it expects does not enforce it: every other key a caller
// invents is accepted, and any key Execute happens to read without publishing
// becomes silently caller-settable. That gap is not hypothetical -- it is a
// finding against the code this framework was ported from, and it is the reason
// this function exists.
//
// Enforcing the published schema at the boundary makes the contract the
// enforced contract for every module, present and future, instead of requiring
// each module's honoured keys to be audited by hand.
//
// In this repository every Validate implementation starts here. That is a rule
// adopted here, and stating it as inherited would be flattering: the helper
// exists in the code this was ported from, but only the two modules the original
// finding was written against actually call it, so seven others still accept
// keys their schema never declared.
//
// A nil schema declares nothing, so every key is undeclared: fail closed, so a
// module that forgets to publish a schema is unusable rather than unguarded.
func ValidateDeclaredParams(schema *JSONSchema, params map[string]any) error {
	var undeclared []string
	for key := range params {
		if schema == nil {
			undeclared = append(undeclared, key)
			continue
		}
		if _, declared := schema.Properties[key]; !declared {
			undeclared = append(undeclared, key)
		}
	}
	if len(undeclared) == 0 {
		return nil
	}
	// Sorted so the message is deterministic, and named so the resulting error
	// tells the caller what to remove instead of leaving them to guess.
	sort.Strings(undeclared)
	return fmt.Errorf("undeclared parameter(s) not present in the module schema: %s",
		strings.Join(undeclared, ", "))
}
