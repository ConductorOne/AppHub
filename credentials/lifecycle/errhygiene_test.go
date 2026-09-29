// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle_test

// The standing error-content invariant, stated over this package by this package.
//
// USOSS-36 brought this package inside the invariant. It was never covered by the
// claim USOSS-7 made -- so this is a gap being closed rather than a regression --
// and it found thirteen refusals rendering caller-supplied text, not the seven the
// ticket listed: annotations.go had eight rather than four, and credentials/lifecycle
// issuance.go had two the ticket did not mention at all.
//
// internal/errhygiene holds the mechanism and the reasoning; this file holds the
// part only this package can write.

import (
	"context"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/credentials/lifecycle",
		Drivers:    hygieneDrivers,
		EmptyPopulations: []errhygiene.Population{
			// This package declares no type with a rendering method and no exported
			// zero-argument method that can produce text: its errors are built by
			// fmt.Errorf over this file's sentinels and its statuses are constants.
			// Both absences are asserted rather than left to a check that quietly
			// does nothing.
			errhygiene.PopulationRenderers,
			errhygiene.PopulationTextProducers,
		},
	})
}

// hygieneProvider is a CredentialProvider that supports nothing, so CheckIssuable
// reaches the refusal that renders the requested type.
type hygieneProvider struct{ id string }

func (p hygieneProvider) ID() string   { return p.id }
func (p hygieneProvider) Name() string { return "hygiene" }
func (p hygieneProvider) CreateCredential(context.Context, credentials.CreateRequest) (*credentials.CreateResult, error) {
	return nil, nil
}
func (p hygieneProvider) RevokeCredential(context.Context, string, credentials.Metadata) error {
	return nil
}
func (p hygieneProvider) GetCredentialStatus(context.Context, string, credentials.Metadata) (credentials.CredentialStatus, error) {
	return credentials.CredentialStatusUnknown, nil
}
func (p hygieneProvider) SupportsDynamic() bool { return false }

var hygieneDrivers = map[string]errhygiene.Driver{
	"lifecycle.(*AnnotationRegistry).Register": {Run: func(_ *testing.T, s string) []any {
		var out []any
		key := lifecycle.AnnotationKey(s)
		// A provider ID that is the sentinel, twice, so the duplicate-registration
		// refusal is reached as well as the first one.
		reg := lifecycle.NewAnnotationRegistry()
		out = append(out,
			reg.Register(s, lifecycle.AnnotationRegion),
			reg.Register(s, lifecycle.AnnotationRegion),
		)
		// Over the schema's key limit, where the refusal reports a count and names
		// the provider. The sentinel is in the provider ID here and not in the keys,
		// because that is the value this branch renders.
		tooMany := make([]lifecycle.AnnotationKey, 0, lifecycle.MaxAnnotationKeys+1)
		for range lifecycle.MaxAnnotationKeys + 1 {
			tooMany = append(tooMany, lifecycle.AnnotationRegion)
		}
		out = append(out, lifecycle.NewAnnotationRegistry().Register(s, tooMany...))
		// A key that is refused by name: over-long, and reading as a secret. Each is
		// run twice, once with the sentinel in the key and once with it in the
		// provider ID, because the refusal wraps a message that names both and the
		// mutation round showed a driver reaching only one of them.
		for _, badKey := range []lifecycle.AnnotationKey{
			key,
			lifecycle.AnnotationKey(s + s),
			lifecycle.AnnotationKey("token-" + s),
			"",
			lifecycle.AnnotationKey("token-" + string(key[:8])),
		} {
			out = append(out,
				lifecycle.NewAnnotationRegistry().Register("constant-provider", badKey),
				lifecycle.NewAnnotationRegistry().Register(s, badKey),
			)
		}
		out = append(out, lifecycle.NewAnnotationRegistry().Register(""))
		// A registry holding no sentinel, so the parameterless probe has something
		// to call. The sentinel-bearing ones are not returned: a registry stores the
		// provider IDs and keys it is handed, so walking one finds them by design,
		// and that is the caller's own data structure rather than anything this
		// package renders.
		clean := lifecycle.NewAnnotationRegistry()
		_ = clean.Register("constant-provider", lifecycle.AnnotationRegion)
		out = append(out, clean)
		return out
	}},

	"lifecycle.(*AnnotationRegistry).Validate": {Run: func(_ *testing.T, s string) []any {
		var out []any
		reg := lifecycle.NewAnnotationRegistry()
		if err := reg.Register("constant-provider", lifecycle.AnnotationRegion); err != nil {
			panic(err)
		}
		// A registry that DECLARES the sentinel as a key, so the over-long-value
		// refusal -- which is reached only for a declared key -- can be driven with
		// the sentinel in the key it names. Without this the value-length branch was
		// never reached with a sentinel key, and the mutation round caught it.
		declared := lifecycle.NewAnnotationRegistry()
		if err := declared.Register("constant-provider", lifecycle.AnnotationKey(s)); err != nil {
			panic(err)
		}
		// One key per call, because Validate iterates a map and two candidate
		// refusals in one call would make which one fires depend on map order.
		out = append(out,
			// An unregistered provider: renders the provider ID.
			reg.Validate(s, lifecycle.Annotations{lifecycle.AnnotationRegion: "eu-west-1"}),
			// An undeclared key: renders the provider ID and the key.
			reg.Validate("constant-provider", lifecycle.Annotations{lifecycle.AnnotationKey(s): "v"}),
			reg.Validate(s, lifecycle.Annotations{lifecycle.AnnotationKey(s): s}),
			// A declared key with an over-long value: renders the key and a length.
			declared.Validate("constant-provider", lifecycle.Annotations{lifecycle.AnnotationKey(s): longValue(s)}),
			// And a value that is long but not over the limit, so the branch above is
			// reached because of the length rather than because of the key.
			declared.Validate("constant-provider", lifecycle.Annotations{lifecycle.AnnotationKey(s): s}),
		)
		// Over the key-count limit, where the refusal reports a count.
		many := lifecycle.Annotations{}
		for i := range 40 {
			many[lifecycle.AnnotationKey(s+string(rune('a'+i)))] = s
		}
		out = append(out, reg.Validate("constant-provider", many))
		return out
	}},

	"lifecycle.CheckIssuable": {Run: func(_ *testing.T, s string) []any {
		t := credentials.CredentialType(s)
		policy := lifecycle.ProviderPolicy{
			Enabled:      true,
			AllowedTypes: []credentials.CredentialType{credentials.CredentialTypeDynamic},
		}
		allowed := lifecycle.ProviderPolicy{
			Enabled:                    true,
			AllowedTypes:               []credentials.CredentialType{t},
			AllowUnrecoverableIssuance: true,
		}
		p := hygieneProvider{id: s}
		return []any{
			// The policy forbids the type: renders the requested type.
			lifecycle.CheckIssuable(p, policy, t),
			// The policy allows it and the provider cannot vend it: renders it again,
			// through a different refusal.
			lifecycle.CheckIssuable(p, allowed, t),
			// And the two refusals that name nothing, so a driver that only ever
			// reaches the constant paths is not what is being checked.
			lifecycle.CheckIssuable(p, lifecycle.ProviderPolicy{}, t),
			lifecycle.CheckIssuable(p, lifecycle.ProviderPolicy{
				Enabled:      true,
				AllowedTypes: []credentials.CredentialType{credentials.CredentialTypeDynamic},
			}, credentials.CredentialTypeDynamic),
		}
	}},

	"lifecycle.CheckScope": {Run: func(_ *testing.T, s string) []any {
		t := credentials.CredentialType(s)
		var out []any
		// A caller with scopes that do not cover the request: the refusal renders
		// the provider ID and the credential type, and reports the TTL.
		for _, scopes := range [][]lifecycle.CallerScope{
			{},
			{{ProviderID: "constant-provider"}},
			{{ProviderID: s, Types: []credentials.CredentialType{credentials.CredentialTypeDynamic}}},
			{{ProviderID: s, Types: []credentials.CredentialType{t}, MaxTTL: time.Minute}},
		} {
			out = append(out, lifecycle.CheckScope(scopes, s, t, time.Hour))
		}
		return out
	}},

	// ---- exemptions ----

	"lifecycle.(*AnnotationRegistry).Declared": {Why: "returns the keys a provider declared and no " +
		"error. Handing back the caller's own declaration is the method's purpose, and the invariant " +
		"is about what an error renders."},
	"lifecycle.(*Record).Expired":       {Why: "returns a bool."},
	"lifecycle.(ProviderPolicy).Allows": {Why: "returns a bool."},
	"lifecycle.(ProviderPolicy).ClampTTL": {Why: "returns a time.Duration, which cannot carry text; a " +
		"quantity is permitted by the invariant."},
	"lifecycle.DispositionForFailure": {Why: "returns a Disposition whose Status and RevokeOutcome are " +
		"chosen from this package's own constants on every branch, including the default one. No " +
		"error, and no value derived from the caller's IssuePhase."},
	"lifecycle.RevokeDisposition": {Why: "classifies the caller's error with errors.Is and returns a " +
		"Disposition built from this package's constants. It returns no error, and it does not " +
		"forward the one it was given -- USOSS-15 records that a failed operation stores a " +
		"classification and never the provider's error text."},
	"lifecycle.ExpiryDisposition": {Why: "the same as RevokeDisposition, plus a Record and a clock. " +
		"Every branch returns a Disposition of this package's constants; nothing from the record or " +
		"the error reaches the result."},
	"lifecycle.StatusFromProvider": {Why: "returns a Status: one of this package's constants for a " +
		"status it recognises, or the current status the caller passed in for one it does not. It " +
		"produces no new text and returns no error."},

	// The interface methods. An interface method has no body here, so what it
	// returns is the implementation's business: credentials/lifecycle/fake and the
	// store are where those live, and each is checked where it is implemented.
	"lifecycle.(Issuer).Issue":                           {Why: interfaceMethod},
	"lifecycle.(Issuer).Revoke":                          {Why: interfaceMethod},
	"lifecycle.(Issuer).ExtendTTL":                       {Why: interfaceMethod},
	"lifecycle.(PolicySource).PolicyFor":                 {Why: interfaceMethod},
	"lifecycle.(ProviderMetadataSource).ResolveMetadata": {Why: interfaceMethod},
	"lifecycle.(Reconciler).Reconcile":                   {Why: interfaceMethod},
	"lifecycle.(Records).Create":                         {Why: interfaceMethod},
	"lifecycle.(Records).Update":                         {Why: interfaceMethod},
	"lifecycle.(Records).Get":                            {Why: interfaceMethod},
	"lifecycle.(Records).Delete":                         {Why: interfaceMethod},
	"lifecycle.(Records).ListByRequester":                {Why: interfaceMethod},
	"lifecycle.(Records).ListByApplication":              {Why: interfaceMethod},
	"lifecycle.(Records).ListByStatus":                   {Why: interfaceMethod},
	"lifecycle.(Records).ListExpiring":                   {Why: interfaceMethod},
	"lifecycle.(SecretWriter).Write":                     {Why: interfaceMethod},
	"lifecycle.(SecretWriter).Delete":                    {Why: interfaceMethod},
}

const interfaceMethod = "an interface method: no body in this package, so what it returns belongs to " +
	"whatever implements it. The implementations in this repository are checked under their own " +
	"packages' subjects; a host's implementation is outside every subject that exists, and the " +
	"candidate ticket for an adopter-runnable conformance helper is the honest way to reach it."

// longValue is a string past MaxAnnotationValueLen built out of the sentinel, so
// the refusal that reports a length is reached with sentinel bytes behind it.
func longValue(s string) string {
	out := s
	for len(out) <= lifecycle.MaxAnnotationValueLen {
		out += s
	}
	return out
}
