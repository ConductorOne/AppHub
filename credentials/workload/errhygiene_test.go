// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package workload_test

// The standing error-content invariant, stated over this package by this package.
//
// USOSS-36 brought this package inside the invariant; it was never covered by the
// claim USOSS-7 made. internal/errhygiene holds the mechanism and the reasoning;
// this file holds the part only this package can write.

import (
	"context"
	"errors"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/workload"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/credentials/workload",
		Drivers:    hygieneDrivers,
		EmptyPopulations: []errhygiene.Population{
			// This package declares no type with a rendering method, and the absence
			// is asserted rather than left to a check that quietly does nothing.
			errhygiene.PopulationRenderers,
		},
	})
}

// rejectingVerifier answers every proof with the package's own refusal, so that
// what VerifierRegistry.Verify returns on the delegating path is a constant this
// fixture chose rather than something an implementation invented.
type rejectingVerifier struct{}

func (rejectingVerifier) Verify(context.Context, workload.ExpectedAttestation, workload.AttestationProof) (workload.Identity, error) {
	return workload.Identity{}, workload.ErrAttestationRejected
}

var hygieneDrivers = map[string]errhygiene.Driver{
	"workload.(*VerifierRegistry).Register": {Run: func(_ *testing.T, s string) []any {
		m := workload.Method(s)
		var out []any
		// A method name that is the sentinel, registered twice, plus the nil-verifier
		// refusal: those are the two sites that render a scheme name.
		reg := workload.NewVerifierRegistry()
		out = append(out,
			reg.Register(m, rejectingVerifier{}),
			reg.Register(m, rejectingVerifier{}),
			workload.NewVerifierRegistry().Register(m, nil),
			workload.NewVerifierRegistry().Register("", rejectingVerifier{}),
		)
		// A registry holding no sentinel, so the parameterless probe has a
		// VerifierRegistry to call Methods on. The sentinel-bearing one is not
		// returned: a registry stores the scheme names it is handed, and Methods
		// hands them back on purpose -- that is the caller's own data structure
		// rather than anything this package renders.
		clean := workload.NewVerifierRegistry()
		_ = clean.Register(workload.MethodK8sServiceAccount, rejectingVerifier{})
		out = append(out, clean)
		return out
	}},

	"workload.(*VerifierRegistry).Verify": {Run: func(_ *testing.T, s string) []any {
		m := workload.Method(s)
		reg := workload.NewVerifierRegistry()
		if err := reg.Register(workload.MethodK8sServiceAccount, rejectingVerifier{}); err != nil {
			panic(err)
		}
		proof := workload.AttestationProof{
			Method: m,
			Proof:  map[string]credentials.Secret{s: credentials.NewSecret(s)},
		}
		expect := func(method workload.Method) workload.ExpectedAttestation {
			return workload.ExpectedAttestation{
				Method: method, Subject: s, Issuer: s, Audience: s,
			}
		}
		var out []any
		// The three refusals this method makes itself: no expected scheme, a proof
		// claiming a different scheme, and a scheme nothing is registered for. Each
		// must be ErrAttestationRejected and nothing more -- distinguishing them
		// would be an oracle, which is the point of the one error.
		for _, expected := range []workload.ExpectedAttestation{
			expect(""),
			expect(workload.MethodK8sServiceAccount),
			expect(m),
		} {
			_, err := reg.Verify(context.Background(), expected, proof)
			out = append(out, err)
		}
		// And the delegating path, where the registered verifier answers. What it
		// returns is its own; what this checks is that the registry adds nothing.
		_, err := reg.Verify(context.Background(),
			expect(workload.MethodK8sServiceAccount),
			workload.AttestationProof{Method: workload.MethodK8sServiceAccount, Proof: proof.Proof})
		out = append(out, err)
		return out
	}},

	"workload.(*VerifierRegistry).For": {Why: "returns (Verifier, bool) and no error. A caller-supplied " +
		"scheme reaches a map lookup and nothing that renders; the duplicate and nil-verifier paths, " +
		"which do return an error, are driven through Register."},

	"workload.(Provisioner).Rotate":     {Why: interfaceMethod},
	"workload.(Provisioner).Materials":  {Why: interfaceMethod},
	"workload.(TokenIssuer).IssueToken": {Why: interfaceMethod},
	"workload.(Verifier).Verify": {Why: "an interface method: no body here, and the normative contract " +
		"already requires every failure to be ErrAttestationRejected -- one error for every failure " +
		"mode, because distinguishing them for an unauthenticated caller is an oracle. What a host's " +
		"verifier returns is outside every subject that exists."},
}

const interfaceMethod = "an interface method: no body in this package, so what it returns belongs to " +
	"whatever implements it, and no implementation exists in this repository yet. When one lands, its " +
	"concrete method appears in that package's derivation and needs a driver there."

// TestRejectingVerifierSatisfiesTheContract keeps the fixture's own double honest:
// a driver double that stopped implementing Verifier would silently stop reaching
// the delegating path.
func TestRejectingVerifierSatisfiesTheContract(t *testing.T) {
	var v workload.Verifier = rejectingVerifier{}
	_, err := v.Verify(context.Background(), workload.ExpectedAttestation{}, workload.AttestationProof{})
	if !errors.Is(err, workload.ErrAttestationRejected) {
		t.Fatalf("the fixture's verifier does not reject: %v", err)
	}
}
