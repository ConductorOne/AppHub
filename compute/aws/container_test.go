// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// The secret resolver these tests wire in.
//
// # Why it is adversarial rather than cooperative
//
// A cooperative fake proves nothing about leakage: it never had the material,
// so a test using it shows only that the port did not invent one. PR #18's
// blocker 3 was exactly this — a "nothing observable" test whose recorder was
// benign, so it could not exercise the path that actually leaked. So this
// resolver behaves like a real one AND carries a sentinel value it actively
// tries to push through every channel the seam exposes: the returned addresses
// and the policy document.
//
// The property the tests below assert is therefore not "the port did not print
// a secret" but "the port cannot: there is no value on this seam at all."
type stubSecrets struct {
	// failWith, when set, is returned instead of resolving.
	failWith error
	// leak, when set, is smuggled into every address and the policy document,
	// so a test can prove the port carries addresses and nothing else.
	leak string
	// wildcard makes the read policy name "*" as its resource, which is the
	// cross-tenant grant the container port must refuse to attach.
	wildcard bool
	// dropsVersion makes this resolver accept a pinned binding and return an
	// address with no revision on it, which is the silent unpinning the port
	// refuses at the seam. A resolver that cannot pin is entitled to say so
	// with compute.ErrVersionPinningUnsupported; one that reports success for
	// a pin it discarded is not.
	dropsVersion bool
	// placement is the placement this resolver claims every secret is stored
	// for. Empty means stubPlacement, the placement the fixtures deploy into,
	// so a test that is not about placements does not have to say so; a test
	// that sets it to anything else is asserting the port's refusal.
	placement string
}

// stubPlacement is the placement serviceFixture's specs land in: they carry no
// [compute.Placement], and Config.placement fills an empty one in with
// [aws.Config.DefaultPlacement], which fullConfig sets to "default".
const stubPlacement = "default"

// sentinelSecretValue is the material an adversarial resolver tries to leak. It
// is not spelled like a hostname or a key: the repository's disclosure scan is
// right to flag those shapes, and a fixture is not a reason to loosen a rule.
const sentinelSecretValue = "SENTINEL-secret-material-must-never-appear"

func (s stubSecrets) SecretParameterARNs(_ context.Context, in []aws.SecretBindingRef) ([]aws.SecretParameterRef, error) {
	if s.failWith != nil {
		return nil, s.failWith
	}
	out := make([]aws.SecretParameterRef, 0, len(in))
	for _, b := range in {
		// A parameter ARN as a real store would report it, with the account
		// position holding a word.
		arn := "arn:aws:ssm:" + aws.MemoryRegion + ":" + aws.MemoryAccount + ":parameter/" +
			strings.TrimPrefix(b.ID, "secret/")
		if s.leak != "" {
			arn += "-" + s.leak
		}
		// The pin, honoured the way SSM does it: a ":<revision>" selector on
		// the ARN. A stub that ignored it would be a fixture that cannot
		// express the property under test, so every test using it would be
		// asserting against the fixture's limitation rather than the port's
		// behaviour.
		ref := aws.SecretParameterRef{EnvName: b.EnvName, ARN: arn}
		if b.Version != "" && !s.dropsVersion {
			ref.Version = b.Version
			ref.ARN = arn + ":" + b.Version
		}
		out = append(out, ref)
	}
	return out, nil
}

func (s stubSecrets) SecretReadPolicy(refs []aws.SecretParameterRef) (string, error) {
	resources := make([]string, 0, len(refs))
	for _, r := range refs {
		resources = append(resources, r.ARN)
	}
	if s.wildcard {
		resources = []string{"*"}
	}
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":      "ReadTheseParametersOnly",
			"Effect":   "Allow",
			"Action":   []string{"ssm:GetParameter", "ssm:GetParameters"},
			"Resource": resources,
		}},
	}
	if s.leak != "" {
		// A hostile store trying to smuggle material through the one document
		// the container port attaches verbatim.
		doc["Comment"] = s.leak
	}
	raw, err := json.Marshal(doc)
	return string(raw), err
}

// SecretPlacement is the fixture's answer to "where does this secret live".
//
// A stub cannot know, so it says what the test told it to say. That is the
// point: the port is the thing under test, and what is being asserted is that
// the port refuses a mismatch rather than that the store computes one
// correctly. The store's own half is asserted against the real SSM store, in
// TestTheProviderResolvesItsOwnSecretsAcrossThePort.
func (s stubSecrets) SecretPlacement(_ context.Context, _ aws.SecretBindingRef) (string, error) {
	if s.failWith != nil {
		return "", s.failWith
	}
	if s.placement == "" {
		return stubPlacement, nil
	}
	return s.placement, nil
}

// --- helpers ------------------------------------------------------------------

// serviceFixture builds a provider, an identity, and a spec that deploys.
func serviceFixture(t *testing.T, mutate func(*aws.Config)) (*aws.Provider, *aws.Substrate, compute.ServiceSpec) {
	t.Helper()
	p, sub := newProvider(t, mutate)
	id, err := p.Identities().EnsureWorkloadIdentity(context.Background(), compute.WorkloadIdentitySpec{
		Name:   "billing",
		RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("ensuring the workload identity: %v", err)
	}
	return p, sub, compute.ServiceSpec{
		Name:      "billing",
		Image:     "example-registry/apphub/billing:v1",
		Resources: compute.Resources{CPUMillicores: 250, MemoryMiB: 512},
		Replicas:  2,
		Identity:  id.Ref,
		Labels:    map[string]string{"team": "payments"},
	}
}

func scheduledJobSpecFromService(spec compute.ServiceSpec) compute.ScheduledJobSpec {
	return compute.ScheduledJobSpec{
		Name:      spec.Name + "-nightly",
		Schedule:  compute.Schedule{Expression: "*/5 * * * *"},
		Image:     spec.Image,
		Resources: spec.Resources,
		Env:       append([]compute.EnvVar(nil), spec.Env...),
		Secrets:   append([]compute.SecretBinding(nil), spec.Secrets...),
		Identity:  spec.Identity,
		Labels:    maps.Clone(spec.Labels),
	}
}

func containers(t *testing.T, p *aws.Provider) compute.ContainerRuntime {
	t.Helper()
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("acquiring the container runtime: %v", err)
	}
	return rt
}

// roleOf returns the IAM role name behind a workload identity ref.
func roleOf(ref compute.Ref) string { return strings.TrimPrefix(ref.ID, "role/") }

// putSecret stores a secret in p's own SSM-backed store and returns its Ref.
//
// Tests that bind a secret get the reference from the store rather than
// composing one, because a composed ID is only ever a valid reference by
// accident: the store's parameter path is built from the configured prefix, the
// scope and the name, and a hand-written "secret/billing/token" is outside that
// prefix and refused. That refusal is correct, and a test relying on it is
// asserting the wrong thing.
//
// placement may be empty, meaning the provider's default.
func putSecret(t *testing.T, p *aws.Provider, name, placement string) compute.Ref {
	t.Helper()
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("acquiring the secret store: %v", err)
	}
	stored, err := store.Put(context.Background(), compute.SecretSpec{
		Name:      name,
		Scope:     "billing",
		Value:     compute.NewSecretValue("value-of-" + name),
		Placement: compute.Placement{Name: placement},
	})
	if err != nil {
		t.Fatalf("storing the secret %q: %v", name, err)
	}
	return stored.Ref
}

// --- the convergence property, over a generated population of junk -----------

// TestEnsureConvergesWhatItOwnsAndLeavesWhatItDoesNot is the property, not a
// case.
//
// The rule it encodes is the corrected one: **converge the sub-namespace you
// own; never touch what you do not own.** "Everything converges" would be wrong
// — it silently deletes an operator's cost-centre tag — and "the expected thing
// is present" would be worse, because an attacker-added entry passes it while
// sitting right next to the expected one.
//
// So the assertion is set EQUALITY over the namespace this port owns, and set
// PRESERVATION over everything else, run against a population of pre-existing
// junk rather than a clean substrate.
func TestEnsureConvergesWhatItOwnsAndLeavesWhatItDoesNot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	// A first deploy that asks for a capability and for exec, so there is
	// something to revoke on the second.
	spec.Capabilities = []compute.WorkloadCapability{compute.WorkloadCapabilityModelInference}
	spec.ExecEnabled = true
	first, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	role := roleOf(spec.Identity)

	// The junk population: things nobody asked for, planted where a merge-rather
	// -than-reconcile implementation would leave them.
	junkPolicies := []string{
		"apphub-cap-not-a-real-capability", // ours by prefix, so it must go
		"apphub-ecs-exec-old",              // ours by prefix, so it must go
		"apphub-secret-read",               // ours, and not wanted on THIS role
	}
	for _, name := range junkPolicies {
		if err := sub.IAM.PutRolePolicy(ctx, role, name,
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}
	// And one an operator attached out of band, which must survive: detaching
	// it is the tag-deletion bug in a more dangerous form.
	const operatorPolicy = "acme-compliance-baseline"
	if err := sub.IAM.PutRolePolicy(ctx, role, operatorPolicy,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`,
	); err != nil {
		t.Fatalf("planting the operator policy: %v", err)
	}

	// Second deploy: no capabilities, no exec. Both must be revoked.
	spec.Capabilities = nil
	spec.ExecEnabled = false
	second, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if first.Revision == second.Revision {
		t.Error("the effective configuration changed but the revision did not, so a caller " +
			"cannot tell a real rollout from a no-op Ensure")
	}

	got := iam.RolePolicies(role)
	// EQUALITY over the namespace we own.
	var ours []string
	for name := range got {
		if strings.HasPrefix(name, "apphub-") {
			ours = append(ours, name)
		}
	}
	sort.Strings(ours)
	if len(ours) != 0 {
		t.Errorf("after an Ensure asking for no capabilities and no exec, the role still carries "+
			"apphub-owned policies %q. Every one of these was either revoked by omission or was "+
			"never asked for, so 'the expected policy is present' would have passed here while a "+
			"grant nobody asked for stayed attached", ours)
	}
	// PRESERVATION over what we do not own.
	if _, ok := got[operatorPolicy]; !ok {
		t.Errorf("the operator's own inline policy %q was removed by an Ensure. Converging a "+
			"namespace this provider does not own is data loss dressed as correctness",
			operatorPolicy)
	}
}

// TestExecAndCapabilitiesConvergeInBothDirections names the class the source
// system fails: attachECSExecPolicy (build.go:670) has no counterpart at all,
// so nothing ever removes the ssmmessages grant.
func TestExecAndCapabilitiesConvergeInBothDirections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	role := roleOf(spec.Identity)

	for _, step := range []struct {
		name  string
		exec  bool
		caps  []compute.WorkloadCapability
		grant bool
		cap   bool
	}{
		{name: "off", exec: false, caps: nil, grant: false, cap: false},
		{name: "exec on", exec: true, caps: nil, grant: true, cap: false},
		{name: "both on", exec: true, caps: []compute.WorkloadCapability{compute.WorkloadCapabilityModelInference}, grant: true, cap: true},
		{name: "exec off, cap on", exec: false, caps: []compute.WorkloadCapability{compute.WorkloadCapabilityModelInference}, grant: false, cap: true},
		{name: "both off again", exec: false, caps: nil, grant: false, cap: false},
	} {
		spec.ExecEnabled = step.exec
		spec.Capabilities = step.caps
		st, err := rt.EnsureService(ctx, spec)
		if err != nil {
			t.Fatalf("%s: ensure: %v", step.name, err)
		}
		got := iam.RolePolicies(role)
		_, hasExec := got["apphub-ecs-exec"]
		_, hasCap := got["apphub-cap-model-inference"]
		if hasExec != step.grant {
			t.Errorf("%s: ssmmessages grant present = %t, want %t", step.name, hasExec, step.grant)
		}
		if hasCap != step.cap {
			t.Errorf("%s: model-inference grant present = %t, want %t", step.name, hasCap, step.cap)
		}
		// The service's own flag has to converge too, not only the grant: the
		// source system passes EnableExecuteCommand unconditionally, so a port
		// that only managed the policy would still leave every task reachable.
		if st.Spec.ExecEnabled != step.exec {
			t.Errorf("%s: the service reports ExecEnabled = %t, want %t",
				step.name, st.Spec.ExecEnabled, step.exec)
		}
	}
}

// --- the secret path ----------------------------------------------------------

// TestTheSecretSeamCannotCarryAValue is a property of the TYPE, not of a call.
//
// The container port must never hold secret material, and the way that is
// guaranteed is that [aws.SecretResolver] has no method that returns any. This
// asserts it by reflection over the interface rather than by reading the code,
// so a method added later that returns a value fails here.
func TestTheSecretSeamCannotCarryAValue(t *testing.T) {
	t.Parallel()
	iface := reflect.TypeOf((*aws.SecretResolver)(nil)).Elem()
	if iface.NumMethod() == 0 {
		t.Fatal("the resolver interface has no methods, so this test proves nothing")
	}
	forbidden := []reflect.Type{
		reflect.TypeOf(compute.SecretValue{}),
	}
	for i := range iface.NumMethod() {
		m := iface.Method(i)
		for j := range m.Type.NumOut() {
			out := m.Type.Out(j)
			for _, bad := range forbidden {
				if out == bad || out.String() == bad.String() {
					t.Errorf("SecretResolver.%s returns %s. The container port must be unable to "+
						"hold secret material, and that has to be true by construction rather "+
						"than by convention", m.Name, out)
				}
			}
		}
	}
}

// TestNoSecretMaterialReachesAnyRenderedArtefact drives an ACTIVELY HOSTILE
// resolver.
//
// The suite's own secret invariant plants its sentinel only for a provider with
// both CapSecretStore and CapContainerService, so it says nothing at all about a
// provider with one of them — and even for a provider with both it is a
// cooperative scan, which proves nothing about leakage: a cooperative fake never
// held the material, so it could not have leaked it. This is the replacement,
// and it is deliberately hostile: the resolver smuggles a sentinel into every
// address it returns and into the policy document it produces, and the test then
// enumerates every surface those can reach.
//
// (This cited "INTERFACE-FRICTION.md §4" for the vacuity claim. No such file has
// ever existed in this repository, here or in any commit. The claim is true and
// is now stated rather than referred to.)
func TestNoSecretMaterialReachesAnyRenderedArtefact(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{leak: sentinelSecretValue}
	})
	rt := containers(t, p)
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "DATABASE_PASSWORD",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "secret/billing/db"},
	}}
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("ensure with secrets: %v", err)
	}

	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}

	// The sentinel is EXPECTED in two places and forbidden everywhere else, so
	// this is an allow-list rather than a ban. The hostile resolver smuggles it
	// into the address it returns, and the port is contractually obliged to pass
	// an address through verbatim — into the task definition's secrets array,
	// where the agent resolves it, and into the read grant that authorises
	// exactly that ARN. A test that simply banned the string would fail on
	// correct behaviour, and one that banned nothing would pass on any.
	var scanned int
	forbid := func(surface, content string) {
		t.Helper()
		scanned++
		if strings.Contains(content, sentinelSecretValue) {
			t.Errorf("the resolved secret address reached %s, which is not a surface it may "+
				"appear on:\n  %s", surface, content)
		}
	}

	defs := ecs.Definitions()
	if len(defs) == 0 {
		t.Fatal("no task definition was registered, so there is nothing to scan")
	}
	// The surfaces are DERIVED from the rendered object rather than listed, so a
	// field added to the task definition is scanned without anyone remembering
	// to add it here. See [stringSurfaces].
	var sawAddress bool
	for i, d := range defs {
		surfaces := map[string]string{}
		stringSurfaces(fmt.Sprintf("taskdef[%d]", i), reflect.ValueOf(d), surfaces)

		// The instrument checks itself before it is trusted: if the walk stops
		// finding fields that certainly exist, it would report a clean scan of
		// nothing.
		for _, must := range []string{
			fmt.Sprintf("taskdef[%d].Family", i),
			fmt.Sprintf("taskdef[%d].Container.Name", i),
			fmt.Sprintf("taskdef[%d].Container.Image", i),
		} {
			if _, ok := surfaces[must]; !ok {
				t.Fatalf("the surface walk did not reach %s, so it is not scanning what it "+
					"claims to; every assertion below would pass over a hole", must)
			}
		}

		// Allowed: the address in the secrets array, and nowhere else. Required,
		// in fact — if the address is NOT here the binding was dropped, and a
		// scan that found nothing anywhere would look identical to a clean pass.
		allowed := map[string]bool{}
		for j, sec := range d.Container.Secrets {
			allowed[fmt.Sprintf("taskdef[%d].Container.Secrets[%d].ValueFrom", i, j)] = true
			if strings.Contains(sec.ValueFrom, sentinelSecretValue) {
				sawAddress = true
			}
		}
		for path, value := range surfaces {
			if allowed[path] {
				continue
			}
			if strings.HasSuffix(path, "(UNEXPORTED, NOT SCANNED)") {
				t.Errorf("%s holds a field this scan cannot read. An unscannable surface on a "+
					"rendered artefact is not a pass, because the material could be in it", path)
				continue
			}
			forbid("the task definition field "+path, value)
		}
	}
	if !sawAddress {
		t.Fatal("the secret address is in no task definition at all, so every assertion below " +
			"would pass over an empty surface: the binding was dropped rather than kept out of " +
			"the wrong places")
	}

	// The execution role: the read grant may name the ARN, nothing else may.
	for name, doc := range iam.RolePolicies("exec-apphub-billing") {
		if name == "apphub-secret-read" {
			continue
		}
		forbid("the execution role policy "+name, doc)
	}
	// And the workload's own role must not carry it at all — it is the agent
	// that resolves a secret, never the workload.
	for name, doc := range iam.RolePolicies(roleOf(spec.Identity)) {
		forbid("the workload identity policy "+name, doc)
	}

	// The service itself: tags and every other rendered line.
	rendered, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	// Nothing is skipped, and the allowance is spent ONCE across the whole output.
	//
	// This is the third construction of this scan and each earlier one closed the
	// case that had been demonstrated to it, which is the population lesson in
	// miniature:
	//
	//   1. A list of five fields. Passed with the address in Container.Name,
	//      because nobody had named Container.Name.
	//   2. A reflective walk plus scrub-by-value. Removed EVERY occurrence, so a
	//      copy of the permitted address was scrubbed away with the real one.
	//   3. A budget renewed per line. Caught a duplicate on the task-definition
	//      line and passed a plant on the SERVICE line, because every line was
	//      handed the definition's allowance again.
	//
	// The address is bound a fixed number of times; it may therefore APPEAR that
	// many times in the rendered output as a whole, not that many times per line.
	// So the allowance is decremented as it is spent, and any occurrence beyond it
	// — same line or any other — survives into the scan below and is reported.
	allowance := map[string]int{}
	for _, d := range defs {
		for _, sec := range d.Container.Secrets {
			allowance[sec.ValueFrom]++
		}
	}
	granted := make(map[string]int, len(allowance))
	for value, n := range allowance {
		granted[value] = n
	}
	for _, line := range rendered {
		scrubbed := line
		for value, left := range allowance {
			spend := strings.Count(scrubbed, value)
			if spend > left {
				spend = left
			}
			scrubbed = strings.Replace(scrubbed, value, "<the permitted secret address>", spend)
			allowance[value] -= spend
		}
		forbid("a rendered artefact", scrubbed)
	}
	// The allowance must be exactly spent. Anything left means the rendered
	// artefacts carry the address FEWER times than it is bound -- so the surface
	// this scan treats as the legitimate one is not the surface it is actually
	// on, and every exemption above was applied somewhere else.
	for value, left := range allowance {
		if left != 0 {
			t.Errorf("%d of the %d permitted occurrence(s) of the secret address were never found "+
				"in the rendered artefacts. The exemption was granted against a surface that does "+
				"not carry it, so it was spent covering something else", left, granted[value])
		}
	}

	if scanned == 0 {
		t.Fatal("this test scanned nothing, so it proves nothing")
	}
	t.Logf("scanned %d surfaces for the resolved address", scanned)

	// Finally the error path, driven rather than assumed: a failure after the
	// address exists must not carry it.
	p2, _, spec2 := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{leak: sentinelSecretValue}
	})
	rt2 := containers(t, p2)
	spec2.Secrets = spec.Secrets
	spec2.Ports = []compute.PortSpec{{Number: 70000}} // refused after resolution
	if _, err := rt2.EnsureService(ctx, spec2); err == nil {
		t.Error("expected the spec to be refused")
	} else if strings.Contains(err.Error(), sentinelSecretValue) {
		t.Errorf("a refusal carried the resolved secret address: %v", err)
	}
}

// TestAWildcardSecretReadPolicyIsRefused is the cross-tenant grant, refused.
//
// The source system's shared execution role is granted ssm:GetParameter on
// `{prefix}/apps/*` (terraform/modules/ecs/iam.tf:44), so every application's
// agent can read every other application's secrets. This port cannot reproduce
// it even if the secret store hands it one.
func TestAWildcardSecretReadPolicyIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{wildcard: true}
	})
	rt := containers(t, p)
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "secret/billing/token"},
	}}
	_, err := rt.EnsureService(ctx, spec)
	if err == nil {
		t.Fatal("a secret-read policy naming the resource \"*\" was accepted. That is the " +
			"cross-tenant grant this provider exists to avoid")
	}
	if !strings.Contains(err.Error(), "wildcard") && !strings.Contains(err.Error(), "*") {
		t.Errorf("the refusal does not say what was wrong: %v", err)
	}
	// And nothing was attached on the way to the refusal.
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	if got := iam.RolePolicies("exec-apphub-billing"); len(got) != 0 {
		t.Errorf("the refusal still attached %v to the execution role", got)
	}
}

// TestSecretsAreRefusedWithoutAResolver pins the fail-closed direction: a
// workload silently started without the secrets it asked for either crashes or
// runs degraded, and neither is the caller's decision to have made for them.
//
// BOTH sources of a resolver are removed, and that is the change that makes this
// test mean what its name says. It used to clear only
// [aws.ContainerConfig.Secrets], which was sufficient while a nil field was the
// end of the search — and once nil began composing the provider's own store, the
// same test went green against a provider that had one, on an unrelated refusal
// (a hand-composed reference outside the configured path prefix). A fail-closed
// test that passes for a second reason is not evidence.
func TestSecretsAreRefusedWithoutAResolver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = nil
		cfg.Secrets = nil
	})
	rt := containers(t, p)
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "parameter/token"},
	}}
	_, err := rt.EnsureService(ctx, spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a spec binding secrets against a provider with no secret store returned %v, "+
			"want ErrInvalidSpec", err)
	}
	// And the refusal names the configuration, not the reference: an operator
	// reading it has to learn that the provider has no store, not that their
	// reference looked wrong.
	if !strings.Contains(err.Error(), "no secret store configured") {
		t.Errorf("the refusal does not name the missing configuration: %v", err)
	}
}

// TestTheProviderResolvesItsOwnSecretsAcrossThePort is the composition, driven.
//
// [aws.SecretResolver]'s doc comment claimed the SSM-backed store satisfied it.
// The compiler disagreed — both method signatures differed — no adapter existed
// anywhere in the repository, and every test and every conformance run resolved
// secrets through stubSecrets. So the port's headline capability, secret
// injection by reference from this provider's own store, had never once been
// composed with the store it names.
//
// This is the end-to-end path with no stub in it: a secret is Put through
// [compute.SecretStore], bound by Ref on a ServiceSpec, and the assertions are
// that the task definition references the ARN the substrate reported for that
// parameter and that the execution role was granted read of exactly it.
//
// The compile-time half of the same claim is the var _ SecretResolver
// assertion beside the adapter, which is what stops the two spellings drifting
// apart again.
func TestTheProviderResolvesItsOwnSecretsAcrossThePort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	ref := putSecret(t, p, "db-password", "")
	spec.Secrets = []compute.SecretBinding{{EnvName: "DATABASE_PASSWORD", Secret: ref}}
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("ensure with a secret from this provider's own store: %v", err)
	}

	// The ARN the substrate reports for that parameter, read back rather than
	// composed — the same rule the provider itself follows.
	meta, err := sub.Parameters.Describe(ctx, paramOf(t, ref))
	if err != nil {
		t.Fatalf("describing the parameter: %v", err)
	}
	if meta.ARN == "" {
		t.Fatal("the substrate reported no ARN, so this test can prove nothing")
	}

	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	defs := ecs.Definitions()
	if len(defs) != 1 {
		t.Fatalf("expected one task definition, got %d", len(defs))
	}
	secrets := defs[0].Container.Secrets
	if len(secrets) != 1 {
		t.Fatalf("the task definition carries %d secret reference(s), want 1", len(secrets))
	}
	if secrets[0].Name != "DATABASE_PASSWORD" || secrets[0].ValueFrom != meta.ARN {
		t.Errorf("the task definition references %q<-%q, want %q<-%q",
			secrets[0].Name, secrets[0].ValueFrom, "DATABASE_PASSWORD", meta.ARN)
	}

	// And the grant is exactly that parameter. Not the prefix, not a wildcard.
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	doc, granted := iam.RolePolicies("exec-apphub-billing")["apphub-secret-read"]
	if !granted {
		t.Fatal("no secret-read grant was attached, so the reference the task holds is unreadable")
	}
	if !strings.Contains(doc, meta.ARN) {
		t.Errorf("the secret-read grant does not name %s: %s", meta.ARN, doc)
	}
	if strings.Contains(doc, "*") {
		t.Errorf("the secret-read grant names a wildcard: %s", doc)
	}
}

// TestASecretFromAnotherPlacementIsRefused is
// security/secrets-do-not-cross-placements, asserted at the port.
//
// It is the invariant that made this port's arrival turn the conformance suite
// red: the check needs both a container service and a secret store, no provider
// had both until now, and when one did there was nothing on the seam that could
// answer where a secret was stored. The store records it (USOSS-26 / #49) and
// [aws.SecretResolver.SecretPlacement] reads it back.
//
// The refusal has to be [compute.ErrInvalidSpec] rather than ErrNotFound: the
// secret exists and the workload exists, and what is wrong is the RELATIONSHIP
// the caller asked for. And it has to happen before any write, because the
// alternative is a task definition whose valueFrom resolves to nothing at
// launch — a container that never starts, reported minutes later as a deploy
// failure rather than now as the spec error it is.
func TestASecretFromAnotherPlacementIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A resolver that reports a placement other than the one the fixture's
	// specs land in. Driven through the stub rather than through a second
	// configured placement so that what is under test is the port's comparison
	// and not the store's bookkeeping, which secret_test.go covers.
	p, sub, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{placement: "somewhere-else"}
	})
	rt := containers(t, p)
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "parameter/token"},
	}}

	_, err := rt.EnsureService(ctx, spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("binding a secret from another placement returned %v, want ErrInvalidSpec", err)
	}
	if !strings.Contains(err.Error(), "somewhere-else") || !strings.Contains(err.Error(), stubPlacement) {
		t.Errorf("the refusal does not name both placements, so an operator cannot see which "+
			"side is wrong: %v", err)
	}

	// Nothing was written on the way to the refusal, and the execution role in
	// particular did not get a read grant on a parameter in another region.
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	if got := iam.RolePolicies("exec-apphub-billing"); len(got) != 0 {
		t.Errorf("the refused Ensure still attached %v to an execution role", got)
	}
	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	if defs := ecs.Definitions(); len(defs) != 0 {
		t.Errorf("the refused Ensure still registered %d task definition(s)", len(defs))
	}

	// The same binding in the placement it was stored for is accepted, so the
	// test above is a refusal of the CROSSING and not of secrets in general.
	p2, _, spec2 := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{placement: stubPlacement}
	})
	spec2.Secrets = spec.Secrets
	if _, err := containers(t, p2).EnsureService(ctx, spec2); err != nil {
		t.Errorf("the same binding within one placement was refused: %v", err)
	}
}

// --- ownership at USE, not at issuance ---------------------------------------

// TestARefThatWasValidOnceIsNotACapability is PR #18's blocker 1, generalised
// and applied to this port before it can reproduce it.
//
// The sharp part is that ownership must be re-established at USE. A Ref is
// issued for a resource this provider created; the resource behind it can then
// be replaced by one it did not. Every method that takes a Ref has to check,
// not just Ensure — so this drives ALL of them rather than naming one.
func TestARefThatWasValidOnceIsNotACapability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	ref := st.Ref

	// Replace the resource behind the still-valid Ref with somebody else's.
	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	ecs.PutUnowned(aws.MemoryCluster, "apphub-billing")

	// Every method that takes the Ref, enumerated. Naming one would leave the
	// others live, which is exactly how the class survived review on #18.
	t.Run("DescribeService", func(t *testing.T) {
		if _, err := rt.DescribeService(ctx, ref); !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("got %v, want ErrNotOwned", err)
		}
	})
	t.Run("ScaleService", func(t *testing.T) {
		if err := rt.ScaleService(ctx, ref, 5); !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("got %v, want ErrNotOwned", err)
		}
	})
	t.Run("DeleteService", func(t *testing.T) {
		if err := rt.DeleteService(ctx, ref); !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("got %v, want ErrNotOwned", err)
		}
		// And it really did not delete it.
		rec, derr := sub.ECS.DescribeService(ctx, aws.MemoryCluster, "apphub-billing")
		if derr != nil {
			t.Fatalf("reading the service back: %v", derr)
		}
		if rec.Status != "ACTIVE" {
			t.Errorf("the unowned service was left in status %q; a refused delete must not have "+
				"deleted anything", rec.Status)
		}
	})
	t.Run("EnsureService", func(t *testing.T) {
		// The refusal, and — as in the DeleteService subtest above — that it
		// really did not write. This substrate has already had one successful
		// Ensure, so the role and the group exist and most writes here would be
		// no-ops; TestARefusedEnsureWritesNothing is the version on a clean
		// substrate, where they would not be.
		before := append(sub.IAM.(*aws.MemoryIAM).Dump(), sub.EC2.(*aws.MemoryEC2).Dump()...)
		if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("got %v, want ErrNotOwned", err)
		}
		after := append(sub.IAM.(*aws.MemoryIAM).Dump(), sub.EC2.(*aws.MemoryEC2).Dump()...)
		if !slices.Equal(before, after) {
			t.Errorf("a refused Ensure changed the substrate:\nbefore %v\nafter  %v", before, after)
		}
	})
}

// TestARefusedEnsureWritesNothing is Blocking 2, on a substrate where the writes
// are not no-ops.
//
// [containerRuntime.EnsureService] used to check ownership LAST: after
// reconcileWorkloadCapabilities, after ensureExecutionRole and after
// ensureServiceSecurityGroup. One Ensure against a name held by a foreign
// service therefore did three things on its way to ErrNotOwned:
//
//   - REVOKED the running workload's grants. Capability reconciliation is
//     declarative in both directions, so a spec with no Capabilities removed the
//     ones the live workload had — an outcome strictly worse than creating
//     something, because it breaks a workload that was working, and reported to
//     the caller as an *ownership* error that says nothing about a revocation.
//   - Created an execution role carrying an SSM read grant.
//   - Created a security group carrying an authorized ingress rule.
//
// Neither of the last two is reapable: DeleteService refuses the same name for
// the same reason, so nothing apphub owns will ever remove them.
//
// TestARefThatWasValidOnceIsNotACapability's EnsureService subtest did exercise
// this path and could not catch it, because it runs after a successful Ensure —
// the role and the group already exist and the writes land on themselves. This
// starts from a clean substrate with the name already taken, which is the state
// the defect needs, and asserts the whole substrate is byte-identical rather
// than that one resource was spared.
func TestARefusedEnsureWritesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	ec2, ok := sub.EC2.(*aws.MemoryEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}

	// A grant the live workload holds, so the revocation half has something to
	// revoke. The spec below asks for nothing, which is the declarative "remove
	// them all" the reconciliation is right to honour — for a service this
	// provider owns.
	if err := sub.IAM.PutRolePolicy(ctx, roleOf(spec.Identity), "apphub-cap-a-live-grant",
		`{"Version":"2012-10-17","Statement":[]}`,
	); err != nil {
		t.Fatalf("planting the live grant: %v", err)
	}

	// Somebody else's service under the name this spec wants. Service names
	// derive from mutable application names, so this is a live collision.
	ecs.PutUnowned(aws.MemoryCluster, "apphub-billing")

	// Ingress and a secret, so the security group and the execution role both
	// have a reason to be written.
	spec.Ingress = []compute.IngressRule{{
		From: compute.Peer{Kind: compute.PeerPlatformIngress},
		Port: 8080,
	}}
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  putSecret(t, p, "token", ""),
	}}

	beforeIAM, beforeEC2 := iam.Dump(), ec2.Dump()
	beforePolicies := iam.RolePolicies(roleOf(spec.Identity))
	beforeDefs := len(ecs.Definitions())

	if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("an Ensure against a foreign service returned %v, want ErrNotOwned", err)
	}

	if got := iam.Dump(); !slices.Equal(beforeIAM, got) {
		t.Errorf("the refused Ensure changed IAM:\nbefore %v\nafter  %v", beforeIAM, got)
	}
	if got := ec2.Dump(); !slices.Equal(beforeEC2, got) {
		t.Errorf("the refused Ensure changed EC2:\nbefore %v\nafter  %v", beforeEC2, got)
	}
	if got := iam.RolePolicies(roleOf(spec.Identity)); !maps.Equal(beforePolicies, got) {
		t.Errorf("the refused Ensure changed the LIVE workload's grants: %v -> %v. A refusal that "+
			"revokes is worse than one that creates: it breaks a workload that was working, and "+
			"the caller was told only that it does not own the service",
			slices.Sorted(maps.Keys(beforePolicies)), slices.Sorted(maps.Keys(got)))
	}
	if got := len(ecs.Definitions()); got != beforeDefs {
		t.Errorf("the refused Ensure registered %d task definition(s)", got-beforeDefs)
	}
	// Named individually as well as by the whole-substrate comparison above,
	// because these two are the resources nothing will ever reap.
	if got := iam.RolePolicies("exec-apphub-billing"); len(got) != 0 {
		t.Errorf("an execution role was created carrying %v; DeleteService refuses this name too, "+
			"so nothing apphub owns will remove it",
			slices.Sorted(maps.Keys(got)))
	}
	if _, err := sub.EC2.DescribeSecurityGroupByName(ctx, "apphub-billing", aws.MemoryVPC); err == nil {
		t.Error("a security group with an authorized ingress rule was created for a service this " +
			"provider then refused to manage, and nothing will reap it")
	}
}

// --- the error mapping, enumerated per method --------------------------------

// TestARetryableSubstrateFailureIsErrTransientOnEveryMethod is the gate the
// conformance suite cannot run for this provider.
//
// A mapping is per-call-site, so this enumerates every method of the port: a
// check on one would pass an implementation that gets EnsureService right and
// ScaleService wrong.
//
// # The denominator, and why the claim needs one
//
// "every method" was a list somebody wrote, and it held three of the port's
// eight while the comment claimed all of them. Now the population is derived
// from compute.ContainerRuntime by reflection and every method is accounted for
// exactly once — driven here, or named in unsupportedMethods with the reason.
// A method added to the port fails this test until somebody decides which it is,
// which is the same denominator discipline failinjection_test.go's wantProbes
// applies to the provider-wide claim.
//
// # What the stated justification used to be
//
// It read: "checks_provider.go skips the ErrTransient check unless the provider
// advertises CapSecretStore, and this one does not, so the single guard on the
// substrate-error mapping does not run (INTERFACE-FRICTION.md §3)." Every clause
// of that is now false. USOSS-32 rewrote the gating — checks_provider.go drives
// every method of every port, so skipping is not reachable by omitting a
// capability — this provider has advertised CapSecretStore since #19, and no
// INTERFACE-FRICTION.md has ever existed in this repository. The suite's own
// output says so: the substrate-error mapping is verified for 15 of 15 methods
// driven across 5 ports.
//
// The test is kept anyway, on the reason above rather than that one: the suite
// drives one method per port and a mapping is per call site.
func TestARetryableSubstrateFailureIsErrTransientOnEveryMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	type call struct {
		name string
		run  func(compute.ContainerRuntime, compute.ServiceSpec, compute.Ref, compute.ScheduledJobSpec, compute.Ref) error
	}
	calls := []call{
		{"EnsureService", func(rt compute.ContainerRuntime, spec compute.ServiceSpec, _ compute.Ref, _ compute.ScheduledJobSpec, _ compute.Ref) error {
			_, err := rt.EnsureService(ctx, spec)
			return err
		}},
		{"DescribeService", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, ref compute.Ref, _ compute.ScheduledJobSpec, _ compute.Ref) error {
			_, err := rt.DescribeService(ctx, ref)
			return err
		}},
		{"WaitForService", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, ref compute.Ref, _ compute.ScheduledJobSpec, _ compute.Ref) error {
			_, err := rt.WaitForService(ctx, ref, 1, compute.WaitOptions{Timeout: time.Second})
			return err
		}},
		{"ScaleService", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, ref compute.Ref, _ compute.ScheduledJobSpec, _ compute.Ref) error {
			return rt.ScaleService(ctx, ref, 3)
		}},
		{"DeleteService", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, ref compute.Ref, _ compute.ScheduledJobSpec, _ compute.Ref) error {
			return rt.DeleteService(ctx, ref)
		}},
		{"EnsureScheduledJob", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, _ compute.Ref, spec compute.ScheduledJobSpec, _ compute.Ref) error {
			_, err := rt.EnsureScheduledJob(ctx, spec)
			return err
		}},
		{"DescribeScheduledJob", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, _ compute.Ref, _ compute.ScheduledJobSpec, ref compute.Ref) error {
			_, err := rt.DescribeScheduledJob(ctx, ref)
			return err
		}},
		{"DeleteScheduledJob", func(rt compute.ContainerRuntime, _ compute.ServiceSpec, _ compute.Ref, _ compute.ScheduledJobSpec, ref compute.Ref) error {
			return rt.DeleteScheduledJob(ctx, ref)
		}},
	}

	driven := map[string]bool{}
	for _, c := range calls {
		driven[c.name] = true
	}
	iface := reflect.TypeOf((*compute.ContainerRuntime)(nil)).Elem()
	if iface.NumMethod() == 0 {
		t.Fatal("the port has no methods, so this test's population is empty and it proves nothing")
	}
	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		if !driven[name] {
			t.Errorf("compute.ContainerRuntime.%s is not driven here. \"every method\" is a "+
				"claim with a population, and an unaccounted method silently narrows it", name)
		}
	}
	for name := range driven {
		if _, ok := iface.MethodByName(name); !ok {
			t.Errorf("this test drives %q, which compute.ContainerRuntime does not declare", name)
		}
	}

	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p, _, spec := serviceFixture(t, nil)
			rt := containers(t, p)
			st, err := rt.EnsureService(ctx, spec)
			if err != nil {
				t.Fatalf("ensure service: %v", err)
			}
			jobSpec := scheduledJobSpecFromService(spec)
			job, err := rt.EnsureScheduledJob(ctx, jobSpec)
			if err != nil {
				t.Fatalf("ensure scheduled job: %v", err)
			}
			stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
			if err != nil {
				t.Fatalf("inducing a transient failure: %v", err)
			}
			defer stop()
			gotErr := c.run(rt, spec, st.Ref, jobSpec, job.Ref)
			if !errors.Is(gotErr, compute.ErrTransient) {
				t.Errorf("%s returned %v, want ErrTransient. A throttle reported as terminal tells "+
					"a caller the spec has to change when the deploy would have succeeded on a "+
					"retry", c.name, gotErr)
			}
			if errors.Is(gotErr, compute.ErrFailed) {
				t.Errorf("%s returned an error matching BOTH ErrTransient and ErrFailed, so a "+
					"caller branching on either gets a different answer", c.name)
			}
			if !p.Harness().InjectionFired() {
				t.Errorf("%s: the substrate reports the arming was never consumed, so this case "+
					"observed a healthy provider rather than a throttled one", c.name)
			}
		})
	}
}

// TestEnsureServiceDoesNotReadAFailedDescribeAsAbsence is the source system's
// defect, named and refused.
//
// container.go:855-861 discards DescribeServices' error and leaves serviceExists
// false, so a throttled read leads to a CreateService against a service that is
// already there. The class is broader than this instance — an error read as
// absence — and it has three known instances in the source.
func TestEnsureServiceDoesNotReadAFailedDescribeAsAbsence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
	if err != nil {
		t.Fatalf("inducing a transient failure: %v", err)
	}
	defer stop()
	if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrTransient) {
		t.Errorf("a throttled describe during Ensure returned %v; it must surface as ErrTransient "+
			"rather than be read as 'the service does not exist'", err)
	}
}

// --- refusals rather than silent omissions -----------------------------------

// TestAReachabilityRuleThisProviderCannotResolveIsRefusedNotWidened is the
// fail-closed direction on the one configuration the source system fails open
// on.
//
// With TRAEFIK_SECURITY_GROUP_ID unset the source opens the application's port
// to 0.0.0.0/0 (build.go:836-848), so a missing piece of configuration becomes
// the widest possible rule. compute/network.go's PeerPlatformIngress doc
// requires the opposite, and this pins it for every peer whose configuration
// can be absent rather than only for the one that motivated it.
func TestAReachabilityRuleThisProviderCannotResolveIsRefusedNotWidened(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		peer  compute.PeerKind
		strip func(*aws.PlacementConfig)
	}{
		{"platform ingress", compute.PeerPlatformIngress, func(pc *aws.PlacementConfig) {
			pc.PlatformIngressSecurityGroups = nil
		}},
		{"control plane", compute.PeerControlPlane, func(pc *aws.PlacementConfig) {
			pc.ControlPlaneSecurityGroups = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, sub, spec := serviceFixture(t, func(cfg *aws.Config) {
				pc := cfg.Placements["default"]
				tc.strip(&pc)
				cfg.Placements["default"] = pc
			})
			rt := containers(t, p)
			spec.Ingress = []compute.IngressRule{{
				From: compute.Peer{Kind: tc.peer},
				Port: 8080,
			}}
			_, err := rt.EnsureService(ctx, spec)
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("an unresolvable %s rule returned %v, want ErrInvalidSpec", tc.name, err)
			}
			// And critically: nothing was widened on the way to the refusal.
			ec2, ok := sub.EC2.(*aws.MemoryEC2)
			if !ok {
				t.Fatal("expected the in-memory EC2 substrate")
			}
			for _, line := range ec2.Dump() {
				if strings.Contains(line, "0.0.0.0/0") || strings.Contains(line, "::/0") {
					t.Errorf("a refused %s rule left an internet-wide rule behind: %s", tc.name, line)
				}
			}
		})
	}
}

func TestScheduledJobsRequireASchedulerSubstrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, func(_ *aws.Config) {})
	sub := aws.NewMemorySubstrate()
	sub.Scheduler = nil
	p2, err := aws.New(sub, fullConfig())
	if err != nil {
		t.Fatalf("constructing provider without Scheduler: %v", err)
	}
	rt := containers(t, p2)
	if p.Capabilities().Has(compute.CapScheduledJob) == p2.Capabilities().Has(compute.CapScheduledJob) {
		t.Fatal("the scheduler-backed and schedulerless providers advertise the same scheduled-job capability")
	}
	var unsupported *compute.UnsupportedError
	_, err = rt.EnsureScheduledJob(ctx, scheduledJobSpecFromService(spec))
	if !errors.As(err, &unsupported) {
		t.Fatalf("EnsureScheduledJob returned %v, want *compute.UnsupportedError", err)
	}
	if unsupported.Capability != compute.CapScheduledJob {
		t.Errorf("the refusal names capability %q, want %q", unsupported.Capability, compute.CapScheduledJob)
	}
}

func TestScheduledJobCreatesSchedulerRoleAndScopedPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	st, err := rt.EnsureScheduledJob(ctx, scheduledJobSpecFromService(spec))
	if err != nil {
		t.Fatalf("EnsureScheduledJob: %v", err)
	}
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected in-memory IAM")
	}
	role, err := iam.GetRole(ctx, "sched-"+strings.TrimPrefix(st.Ref.ID, "schedule/"))
	if err != nil {
		t.Fatalf("scheduler role was not created: %v", err)
	}
	if !strings.Contains(role.AssumeRolePolicy, "scheduler.amazonaws.com") {
		t.Fatalf("scheduler role trust policy does not trust scheduler.amazonaws.com: %s", role.AssumeRolePolicy)
	}
	policies := iam.RolePolicies(role.Name)
	doc := policies["apphub-scheduler-run"]
	if doc == "" {
		t.Fatalf("scheduler role policies are %v, want apphub-scheduler-run", policies)
	}
	if strings.Contains(doc, `"Resource":"*"`) || strings.Contains(doc, `"Resource":["*"]`) {
		t.Fatalf("scheduler RunTask policy is wildcard-scoped: %s", doc)
	}
	if !strings.Contains(doc, "ecs:RunTask") || !strings.Contains(doc, "task-definition/job-") {
		t.Fatalf("scheduler policy does not scope ecs:RunTask to the job task definition family: %s", doc)
	}
	if !strings.Contains(doc, roleOf(spec.Identity)) {
		t.Fatalf("scheduler policy does not pass the workload role the job runs as: %s", doc)
	}
}

func TestScheduledJobScheduleGrammarAndTranslation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	translations := map[string]string{
		"*/5 * * * *":      "cron(*/5 * * * ? *)",
		"0 3 1 * *":        "cron(0 3 1 * ? *)",
		"0 9 * * 1-5":      "cron(0 9 ? * MON-FRI *)",
		"30 6 * * 0,6":     "cron(30 6 ? * SUN,SAT *)",
		"0 0 * 1 0-2,4":    "cron(0 0 ? 1 SUN-TUE,THU *)",
		"rate(15 minutes)": "rate(15 minutes)",
	}
	for expr, want := range translations {
		p, sub, spec := serviceFixture(t, nil)
		rt := containers(t, p)
		job := scheduledJobSpecFromService(spec)
		job.Schedule = compute.Schedule{Expression: expr, Paused: true}
		st, err := rt.EnsureScheduledJob(ctx, job)
		if err != nil {
			t.Fatalf("EnsureScheduledJob(%q): %v", expr, err)
		}
		scheduler, ok := sub.Scheduler.(*aws.MemoryScheduler)
		if !ok {
			t.Fatal("expected in-memory scheduler")
		}
		name := strings.TrimPrefix(st.Ref.ID, "schedule/")
		rec, err := scheduler.DescribeSchedule(ctx, name, name)
		if err != nil {
			t.Fatalf("DescribeSchedule: %v", err)
		}
		if rec.Expression != want {
			t.Fatalf("%q translated to %q, want %q", expr, rec.Expression, want)
		}
		if st.Schedule.Expression != expr || !st.Schedule.Paused {
			t.Fatalf("Describe returned schedule %+v, want expression %q and paused", st.Schedule, expr)
		}
	}
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	for _, bad := range []string{
		"", "* * * *", "cron(0 3 * * ? *)", "0 3 * * ? *", "rate(0 minutes)", "rate(5 fortnights)",
		"0 3 1 * 1", "0 3 * * 7", "0 3 * * */2", "0 3 * * 5-1", "0 3 * * 1-", "0 3 * * 12",
	} {
		job := scheduledJobSpecFromService(spec)
		job.Schedule.Expression = bad
		if _, err := rt.EnsureScheduledJob(ctx, job); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("EnsureScheduledJob(%q) returned %v, want compute.ErrInvalidSpec", bad, err)
		}
	}
	if lines := sub.Scheduler.(*aws.MemoryScheduler).Dump(); len(lines) != 0 {
		t.Fatalf("invalid schedules wrote to Scheduler: %v", lines)
	}
}

func TestScheduledJobDescribeReportsMissingDefaultPlacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	st, err := rt.EnsureScheduledJob(ctx, scheduledJobSpecFromService(spec))
	if err != nil {
		t.Fatalf("EnsureScheduledJob: %v", err)
	}
	p2 := newProviderOver(t, sub, func(cfg *aws.Config) {
		cfg.DefaultPlacement = ""
	})
	rt2 := containers(t, p2)
	scheduler, ok := sub.Scheduler.(*aws.MemoryScheduler)
	if !ok {
		t.Fatal("expected in-memory scheduler")
	}
	name := strings.TrimPrefix(st.Ref.ID, "schedule/")
	rec, err := scheduler.DescribeSchedule(ctx, name, name)
	if err != nil {
		t.Fatalf("DescribeSchedule: %v", err)
	}
	rec.Target.ClusterARN = ""
	if _, err := scheduler.UpdateSchedule(ctx, aws.ScheduleRequest{
		GroupName:  name,
		Name:       name,
		Expression: rec.Expression,
		Timezone:   rec.Timezone,
		Paused:     rec.State != "ENABLED",
		Target:     rec.Target,
	}); err != nil {
		t.Fatalf("poisoning schedule target: %v", err)
	}
	_, err = rt2.DescribeScheduledJob(ctx, st.Ref)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("DescribeScheduledJob returned %v, want ErrInvalidSpec from the missing default placement", err)
	}
}

// --- task sizing --------------------------------------------------------------

// TestATaskSizeIsNeverRoundedDown is the invariant [compute.Resources] states:
// rounding down turns a capacity decision into a silent, intermittent
// out-of-memory failure at runtime.
//
// It is asserted as a property over a generated population rather than on a
// handful of chosen pairs, because the interesting cases are the ones nobody
// thinks to name — a memory request that rounds past its tier's ceiling, in
// particular.
func TestATaskSizeIsNeverRoundedDown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var checked int
	for _, milli := range []int{1, 100, 250, 256, 500, 1000, 1024, 1500, 2000, 4000, 8000, 16000} {
		for _, mib := range []int{1, 128, 512, 900, 1024, 1536, 2048, 3000, 4096, 12000, 30000, 60000} {
			p, sub, spec := serviceFixture(t, nil)
			rt := containers(t, p)
			spec.Resources = compute.Resources{CPUMillicores: milli, MemoryMiB: mib}
			st, err := rt.EnsureService(ctx, spec)
			if err != nil {
				// Refusing is legal — but only for a request too large to
				// honour, never for one it could have rounded up.
				if !errors.Is(err, compute.ErrInvalidSpec) {
					t.Errorf("%dm/%dMiB: %v", milli, mib, err)
				}
				continue
			}
			ecs, ok := sub.ECS.(*aws.MemoryECS)
			if !ok {
				t.Fatal("expected the in-memory ECS substrate")
			}
			defs := ecs.Definitions()
			if len(defs) == 0 {
				t.Fatalf("%dm/%dMiB: no task definition was registered", milli, mib)
			}
			got := defs[len(defs)-1]
			// 1000 millicores is one core is 1024 ECS units.
			wantUnits := (milli*1024 + 999) / 1000
			if got.CPUUnits < wantUnits {
				t.Errorf("%dm CPU became %d ECS units, which is LESS than the %d requested",
					milli, got.CPUUnits, wantUnits)
			}
			if got.MemoryMiB < mib {
				t.Errorf("%d MiB became %d MiB, which is less than requested. Rounding a memory "+
					"request down is an out-of-memory kill at runtime", mib, got.MemoryMiB)
			}
			if got.MemoryMiB != mib && st.Message == "" {
				t.Errorf("%dm/%dMiB was rounded to %d units/%d MiB and the status says nothing; "+
					"the caller's only notice of an adjusted allocation is Status.Message",
					milli, mib, got.CPUUnits, got.MemoryMiB)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no size was actually resolved, so this test proved nothing")
	}
}

// --- pausing and scaling ------------------------------------------------------

// TestReplicasZeroPausesAndIsReported covers the state the source system cannot
// express at all: DesiredCount is hardcoded to 1 on create and on update
// (container.go:877, :899).
//
// A paused service has converged, so it is PhaseReady with a message rather
// than PhasePending. Reporting Pending would leave a caller waiting for a state
// the substrate is already in.
func TestReplicasZeroPausesAndIsReported(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	spec.Replicas = 0
	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if st.Phase != compute.PhaseReady {
		t.Errorf("a paused service reports phase %q, want %q; a caller waiting for convergence "+
			"would wait forever", st.Phase, compute.PhaseReady)
	}
	if !strings.Contains(strings.ToLower(st.Message), "paused") {
		t.Errorf("a paused service's message is %q and does not say it is paused", st.Message)
	}
	if st.DesiredReplicas != 0 {
		t.Errorf("DesiredReplicas = %d, want 0", st.DesiredReplicas)
	}
}

// TestScaleDoesNotRollTheService pins the promise
// [compute.ContainerRuntime.ScaleService] makes: it changes the count "without
// otherwise changing the spec".
//
// An UpdateService carrying a task definition would roll the service as a side
// effect of scaling it, so the revision must not move.
func TestScaleDoesNotRollTheService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	before, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := rt.ScaleService(ctx, before.Ref, 7); err != nil {
		t.Fatalf("scale: %v", err)
	}
	after, err := rt.DescribeService(ctx, before.Ref)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if after.Revision != before.Revision {
		t.Errorf("scaling changed the revision from %q to %q, so it rolled the service as a side "+
			"effect of changing its instance count", before.Revision, after.Revision)
	}
	if after.DesiredReplicas != 7 {
		t.Errorf("DesiredReplicas = %d after scaling to 7", after.DesiredReplicas)
	}
}

// --- waiting -----------------------------------------------------------------

// TestWaitRespectsMinReadyAndReportsTheSubstrateEvent covers both halves of the
// source system's wait defect: it returns as soon as RunningCount is above zero,
// ignoring how many were asked for (container.go:1113-1116), and its timeout is
// a fixed sixty iterations regardless of the caller's deadline.
func TestWaitRespectsMinReadyAndReportsTheSubstrateEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	spec.Replicas = 3
	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	ecs.SetEvents(aws.MemoryCluster, "apphub-billing", "unable to place a task because no "+
		"container instance met all of its requirements")
	resume := ecs.Stall()

	// Nothing is running and nothing will start, so a wait must time out rather
	// than succeed.
	_, err = rt.WaitForService(ctx, st.Ref, 1, compute.WaitOptions{Timeout: 50 * time.Millisecond})
	if !errors.Is(err, compute.ErrTimeout) {
		t.Fatalf("waiting for a service with nothing running returned %v, want ErrTimeout", err)
	}
	if !strings.Contains(err.Error(), "unable to place a task") {
		t.Errorf("the timeout does not relay the substrate's event, which is the only diagnosis "+
			"ECS offers for a task that will never start: %v", err)
	}

	// Now let the substrate start them, and the same wait succeeds.
	resume()
	ecs.Advance(aws.MemoryCluster, "apphub-billing")
	got, err := rt.WaitForService(ctx, st.Ref, 3, compute.WaitOptions{Timeout: time.Second})
	if err != nil {
		t.Fatalf("waiting for a running service: %v", err)
	}
	if got.ReadyReplicas != 3 {
		t.Errorf("ReadyReplicas = %d, want 3", got.ReadyReplicas)
	}
}

// TestAWaitWithNoDeadlineIsRefused is what [compute.WaitOptions] requires: a
// provider must return ErrInvalidSpec rather than wait forever.
func TestAWaitWithNoDeadlineIsRefused(t *testing.T) {
	t.Parallel()
	p, _, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	st, err := rt.EnsureService(context.Background(), spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	_, err = rt.WaitForService(context.Background(), st.Ref, 1, compute.WaitOptions{})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a wait with neither a timeout nor a context deadline returned %v, want "+
			"ErrInvalidSpec", err)
	}
}

// --- teardown -----------------------------------------------------------------

// TestDeleteRemovesTheExecutionRoleItCreatedAndNothingElse.
//
// The execution role is this port's own and exists only to start this service,
// so teardown owns it. The workload identity is NOT this port's, and deleting it
// would take an identity other resources may still be granting access to.
func TestDeleteRemovesTheExecutionRoleItCreatedAndNothingElse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := sub.IAM.GetRole(ctx, "exec-apphub-billing"); err != nil {
		t.Fatalf("the execution role was not created: %v", err)
	}
	if err := rt.DeleteService(ctx, st.Ref); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := sub.IAM.GetRole(ctx, "exec-apphub-billing"); !errors.Is(err, aws.ErrNoSuchResource) {
		t.Errorf("the execution role survived teardown (%v); it exists only to start this "+
			"service, so nothing else will ever delete it", err)
	}
	// The workload identity must survive.
	if _, err := sub.IAM.GetRole(ctx, roleOf(spec.Identity)); err != nil {
		t.Errorf("deleting the service deleted the workload identity %q: %v",
			roleOf(spec.Identity), err)
	}
	// Idempotent.
	if err := rt.DeleteService(ctx, st.Ref); err != nil {
		t.Errorf("a second delete returned %v, want nil", err)
	}
}

// lingeringGroupEC2 refuses the first DeleteSecurityGroup the way EC2 does while a
// drained task's network interface is still attached: DependencyViolation, which
// the SDK adapter classifies as [aws.ErrConflict].
type lingeringGroupEC2 struct {
	aws.EC2API
	refuses int
	deletes int
}

func (l *lingeringGroupEC2) DeleteSecurityGroup(ctx context.Context, id string) error {
	l.deletes++
	if l.refuses > 0 {
		l.refuses--
		return fmt.Errorf("%w: DependencyViolation: resource %s has a dependent object",
			aws.ErrConflict, id)
	}
	return l.EC2API.DeleteSecurityGroup(ctx, id)
}

// TestDeleteServiceConvergesWhenItsSecurityGroupIsStillInUse is the teardown a
// running service really gets: ECS deletes the service, the tasks drain, and the
// security group refuses deletion until their interfaces are released.
//
// The first pass must answer ErrTransient so a retrying caller comes back. The
// second pass is the half that used to be wrong in a way the in-memory ECS hid:
// the service is INACTIVE by then, and ECS refuses to delete an INACTIVE service
// with an error the adapter classifies as transient. A retry that re-issued the
// ECS delete would answer "try again" forever and never reach the group, so the
// count of group deletes is asserted as well as the nil.
func TestDeleteServiceConvergesWhenItsSecurityGroupIsStillInUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	lingering := &lingeringGroupEC2{EC2API: sub.EC2, refuses: 1}
	sub.EC2 = lingering

	if err := rt.DeleteService(ctx, st.Ref); !errors.Is(err, compute.ErrTransient) {
		t.Fatalf("the first DeleteService, refused at the security group, = %v, want "+
			"compute.ErrTransient; a teardown loop that retries only ErrTransient stops here", err)
	}
	if lingering.deletes != 1 {
		t.Fatalf("the first pass made %d security-group deletes, want 1; the armed refusal was "+
			"not what failed it", lingering.deletes)
	}
	if err := rt.DeleteService(ctx, st.Ref); err != nil {
		t.Fatalf("the retry, with the interfaces released, = %v, want nil", err)
	}
	if lingering.deletes != 2 {
		t.Errorf("the retry made %d security-group deletes in total, want 2: it did not reach "+
			"the group", lingering.deletes)
	}
	if _, err := sub.IAM.GetRole(ctx, "exec-apphub-billing"); !errors.Is(err, aws.ErrNoSuchResource) {
		t.Errorf("the execution role survived the converged teardown: %v", err)
	}
}

// TestDeleteServiceRevokesTheDatabasesIngressRuleFirst pins the teardown that
// used to loop forever: a service with a relational database carries a rule on
// the database's group naming the service's own group (see
// [Plan.RelationalIngress] in modules/deploy), and teardown deletes the
// workload before the database. Deleting the service's group while that rule
// still named it hit EC2's DependencyViolation on every attempt, not just the
// first -- unlike the lingering-ENI case in
// [TestDeleteServiceConvergesWhenItsSecurityGroupIsStillInUse], a rule on
// another group never clears by itself, so a teardown that only retried never
// converged.
func TestDeleteServiceRevokesTheDatabasesIngressRuleFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	svc, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensuring the service: %v", err)
	}
	groupID, err := p.WorkloadSecurityGroupID(ctx, svc.Ref)
	if err != nil {
		t.Fatalf("the service's own security group: %v", err)
	}

	db := relationalSpec(spec.Name)
	db.Ingress = append(db.Ingress, compute.IngressRule{
		From: compute.Peer{Kind: compute.PeerWorkload, Workload: svc.Ref},
		Port: 5432,
	})
	if _, err := mustRelational(t, p).EnsureRelational(ctx, db); err != nil {
		t.Fatalf("a database refused its own application as a peer: %v", err)
	}

	ec2, ok := sub.EC2.(*aws.MemoryEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}
	if !groupIsReferenced(ec2.Groups(), groupID) {
		t.Fatalf("no group's ingress names the service's own group %s; the fixture is not "+
			"exercising the dependency this test is about", groupID)
	}

	if err := rt.DeleteService(ctx, svc.Ref); err != nil {
		t.Fatalf("DeleteService = %v, want nil: the database's rule naming the workload's group "+
			"must be revoked, not left to block the delete forever", err)
	}
	if _, err := sub.EC2.DescribeSecurityGroupByName(ctx, "apphub-billing", aws.MemoryVPC); !errors.Is(err, aws.ErrNoSuchResource) {
		t.Errorf("the service's security group survived: %v", err)
	}
	if groupIsReferenced(ec2.Groups(), groupID) {
		t.Errorf("a group still carries a rule sourced from the deleted group %s", groupID)
	}

	// Idempotent: a retried teardown, with the group and the rule already
	// gone, must not fail either.
	if err := rt.DeleteService(ctx, svc.Ref); err != nil {
		t.Errorf("a second DeleteService returned %v, want nil", err)
	}
}

// groupIsReferenced reports whether any group's ingress names id as a source.
func groupIsReferenced(groups []*aws.SecurityGroupRecord, id string) bool {
	for _, g := range groups {
		for _, r := range g.Ingress {
			if r.SourceGroup == id {
				return true
			}
		}
	}
	return false
}

// TestDeleteIsIdempotentBeforeAnythingExists covers the half of teardown that
// runs when a deploy failed between creating the role and creating the service.
func TestDeleteIsIdempotentBeforeAnythingExists(t *testing.T) {
	t.Parallel()
	p, _, _ := serviceFixture(t, nil)
	rt := containers(t, p)
	ref := compute.Ref{Provider: p.Name(), Kind: compute.KindService, ID: "service/apphub-ghost"}
	if err := rt.DeleteService(context.Background(), ref); err != nil {
		t.Errorf("deleting a service that never existed returned %v, want nil", err)
	}
}

// TestIngressConvergesFullyIncludingTheRevokeHalf is the property behind the
// finding that started this port's ingress work.
//
// Without a revoke, ingress only ever accumulates: every rule ever requested
// stays authorised for ever, and "I removed that rule" silently means "I stopped
// asking for it". That is a security control that reports success and does
// nothing, and it is invisible to any test that checks the expected rule is
// PRESENT — the attacker-added rule sits happily next to it.
//
// So the assertion is set EQUALITY against a population of pre-existing junk,
// and the junk includes an internet-wide rule, which is the one that matters.
// Unlike tags, EVERY rule on this group is in scope for removal: the group is
// created by this provider for one service and carries the ownership marker, so
// a rule on it that apphub did not put there is a hole rather than an
// operator's deliberate configuration.
func TestIngressConvergesFullyIncludingTheRevokeHalf(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	spec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerPlatformIngress}, Port: 8080, Description: "kept"},
		{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 5432, Description: "dropped later"},
	}
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	ec2, ok := sub.EC2.(*aws.MemoryEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}
	group, err := ec2.DescribeSecurityGroupByName(ctx, "apphub-billing", aws.MemoryVPC)
	if err != nil {
		t.Fatalf("reading the service's security group: %v", err)
	}

	// The junk: rules nobody asked for, including the one that is a hole.
	junk := []aws.SecurityGroupRule{
		{Protocol: "tcp", FromPort: aws.Port(22), ToPort: aws.Port(22), SourceCIDR: "0.0.0.0/0", Description: aws.Text("someone opened ssh")},
		{Protocol: "tcp", FromPort: aws.Port(8080), ToPort: aws.Port(8080), SourceCIDR: "0.0.0.0/0", Description: aws.Text("widened by hand")},
		{Protocol: "udp", FromPort: aws.Port(53), ToPort: aws.Port(53), SourceGroup: "group-stranger", Description: aws.Text("unexplained")},
		// A RANGE, which an earlier revision could see and could not revoke.
		{Protocol: "tcp", FromPort: aws.Port(1024), ToPort: aws.Port(65535), SourceCIDR: "0.0.0.0/0", Description: aws.Text("wide open")},
	}
	if err := ec2.AuthorizeIngress(ctx, group.ID, junk); err != nil {
		t.Fatalf("planting junk rules: %v", err)
	}

	// Second Ensure drops the control-plane rule and asks for nothing else.
	spec.Ingress = spec.Ingress[:1]
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	after, err := ec2.DescribeSecurityGroupByName(ctx, "apphub-billing", aws.MemoryVPC)
	if err != nil {
		t.Fatalf("reading the group back: %v", err)
	}

	// EQUALITY, not presence. Exactly one platform-ingress rule on 8080.
	want := []aws.SecurityGroupRule{{
		Protocol:    "tcp",
		FromPort:    aws.Port(8080),
		ToPort:      aws.Port(8080),
		SourceGroup: "group-platform-ingress",
		Description: aws.Text("kept"),
	}}
	if len(after.Ingress) != len(want) {
		t.Fatalf("the group holds %d rule(s), want exactly %d.\ngot:  %+v\nwant: %+v",
			len(after.Ingress), len(want), after.Ingress, want)
	}
	if after.Ingress[0] != want[0] {
		t.Errorf("the surviving rule is %+v, want %+v", after.Ingress[0], want[0])
	}
	for _, r := range after.Ingress {
		if r.SourceCIDR == "0.0.0.0/0" || r.SourceCIDR == "::/0" {
			t.Errorf("an internet-wide rule survived convergence: %+v. This is the case that "+
				"matters: a rule nobody asked for on a group this provider owns is a hole, and "+
				"'the expected rule is present' would have passed here", r)
		}
	}
}

// TestPeerInternetOpensBothAddressFamilies.
//
// A rule that opened only 0.0.0.0/0 would leave an IPv6-reachable workload
// unreachable on the address it actually has, and an operator would add ::/0 by
// hand — which then survives every convergence because apphub did not put it
// there and would revoke it if it had. Naming both is the honest reading of what
// PeerInternet means.
func TestPeerInternetOpensBothAddressFamilies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	spec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerInternet}, Port: 443},
	}
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	ec2, ok := sub.EC2.(*aws.MemoryEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}
	group, err := ec2.DescribeSecurityGroupByName(ctx, "apphub-billing", aws.MemoryVPC)
	if err != nil {
		t.Fatalf("reading the group: %v", err)
	}
	var v4, v6 bool
	for _, r := range group.Ingress {
		switch r.SourceCIDR {
		case "0.0.0.0/0":
			v4 = true
		case "::/0":
			v6 = true
		}
	}
	if !v4 || !v6 {
		t.Errorf("PeerInternet on 443 produced v4=%t v6=%t; both are needed or the workload is "+
			"unreachable on one of the addresses it has", v4, v6)
	}
	// And it stays idempotent: a second Ensure must not try to re-authorise
	// what is already there, which EC2 rejects.
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Errorf("a second identical ensure failed, so the compiler is not idempotent: %v", err)
	}
}

// TestAPublicPathWithoutRequireAuthIsRefused pins the semantic that is not
// obvious from the field names, and that a port can get wrong in a way that
// fails open.
//
// PublicPaths is the authentication EXEMPTION set — the base router carries the
// auth middleware and each public path gets its own higher-priority router
// without it (source system @ backend/internal/modules/deploy/container.go).
// So a public path on a route
// that never authenticated means nothing, and silently accepting it lets a
// caller believe an exemption is in force on a route that has no authentication
// to be exempt from.
func TestAPublicPathWithoutRequireAuthIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.IngressAuthMiddleware = "oauth-auth"
	})
	rt := containers(t, p)
	spec.Routes = []compute.Route{{
		Host:           "billing.invalid",
		TargetPort:     8080,
		AllowPlaintext: true,
		PublicPaths:    []string{"/healthz"},
	}}
	if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a public path on an unauthenticated route returned %v, want ErrInvalidSpec", err)
	}
}

// TestAuthenticationIsRefusedWithoutAMiddlewareToDoIt is the other half: a route
// that asks for authentication against a provider that cannot authenticate must
// be refused, not deployed.
//
// The alternative is a route that reports deployed and serves the application to
// anyone who finds its hostname.
func TestAuthenticationIsRefusedWithoutAMiddlewareToDoIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.IngressAuthMiddleware = ""
	})
	rt := containers(t, p)
	spec.Routes = []compute.Route{{
		Host:           "billing.invalid",
		TargetPort:     8080,
		AllowPlaintext: true,
		RequireAuth:    true,
	}}
	if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a route requiring auth on a provider with no middleware returned %v, want "+
			"ErrInvalidSpec", err)
	}
	if p.Capabilities().Has(compute.CapIngressAuth) {
		t.Error("the provider advertises CapIngressAuth with no middleware configured")
	}
}

func TestHostedMCPRouteCarriesOAuthDiscoveryAndCredentialBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	if !p.Capabilities().Has(compute.CapMCPAuth) {
		t.Fatal("the configured MCP auth backend was not advertised")
	}
	spec.Routes = []compute.Route{{
		Host:                 "billing.invalid",
		TargetPort:           8080,
		AllowPlaintext:       true,
		MCPAuthApplicationID: "018f3f85-9b61-7b70-bc24-38426ea34e21",
	}}
	if _, err := containers(t, p).EnsureService(ctx, spec); err != nil {
		t.Fatalf("ensure MCP route: %v", err)
	}
	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	definitions := ecs.Definitions()
	if len(definitions) != 1 {
		t.Fatalf("registered %d task definitions, want 1", len(definitions))
	}
	labels := definitions[0].Container.DockerLabels
	want := map[string]string{
		"traefik.http.routers.apphub-billing-0-mcp.rule":                                                 "Host(`billing.invalid`) && (Path(`/mcp`) || PathPrefix(`/mcp/`))",
		"traefik.http.routers.apphub-billing-0-mcp.priority":                                             "6000",
		"traefik.http.routers.apphub-billing-0-mcp.middlewares":                                          "apphub-billing-0-identity-strip,apphub-billing-0-mcp-context,apphub-billing-0-mcp-auth,apphub-billing-0-mcp-strip,apphub-strip-sso-cookie@ecs",
		"traefik.http.middlewares.apphub-billing-0-mcp-auth.forwardauth.address":                         "http://127.0.0.1:8080/authz/app-mcp",
		"traefik.http.middlewares.apphub-billing-0-mcp-auth.forwardauth.authrequestheaders":              "Authorization,X-AppHub-Application-ID,X-AppHub-MCP-Host",
		"traefik.http.middlewares.apphub-billing-0-mcp-auth.forwardauth.authresponseheaders":             "X-AppHub-User-ID,X-AppHub-Email",
		"traefik.http.middlewares.apphub-billing-0-mcp-strip.headers.customrequestheaders.Authorization": "",
		"traefik.http.routers.apphub-billing-0-mcp-discovery.priority":                                   "6000",
		"traefik.http.services.apphub-billing-0-mcp-discovery.loadbalancer.server.url":                   "http://127.0.0.1:8080",
		"traefik.http.middlewares.apphub-billing-0-mcp-discovery-path.replacepath.path":                  "/.well-known/oauth-protected-resource/mcp/apps/018f3f85-9b61-7b70-bc24-38426ea34e21/billing.invalid",
	}
	for key, value := range want {
		if labels[key] != value {
			t.Errorf("%s = %q, want %q", key, labels[key], value)
		}
	}
	if got := labels["traefik.http.routers.apphub-billing-0.middlewares"]; got != "apphub-billing-0-identity-strip,apphub-strip-sso-cookie@ecs" {
		t.Errorf("base application route middlewares = %q; only /mcp should be authenticated", got)
	}
}

func TestHostedMCPRouteIsRefusedWithoutItsBackend(t *testing.T) {
	t.Parallel()
	p, _, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.MCPAuthBackendURL = ""
	})
	spec.Routes = []compute.Route{{
		Host:                 "billing.invalid",
		TargetPort:           8080,
		AllowPlaintext:       true,
		MCPAuthApplicationID: "018f3f85-9b61-7b70-bc24-38426ea34e21",
	}}
	if _, err := containers(t, p).EnsureService(context.Background(), spec); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("MCP auth without a backend returned %v, want ErrInvalidSpec", err)
	}
	if p.Capabilities().Has(compute.CapMCPAuth) {
		t.Error("the provider advertises MCP auth without a configured backend")
	}
}

// TestAnUnresolvableCertificateIsRefused: a TLS reference that resolves to
// nothing must not be served without the certificate the caller asked for.
func TestAnUnresolvableCertificateIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	spec.Routes = []compute.Route{{
		Host:       "billing.invalid",
		TargetPort: 8080,
		TLS:        &compute.TLSConfig{CertificateRef: "no-such-certificate"},
	}}
	if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("an unresolvable certificate reference returned %v, want ErrInvalidSpec", err)
	}
}

// TestReadinessIsAboutTheRevisionAskedFor, not about tasks of any revision.
//
// ECS's service-level RunningCount counts tasks of EVERY deployment, so
// immediately after an update it already equals DesiredCount while nothing of
// the new revision has started. A provider that read only that count would
// report a rollout complete before it began — and a caller that waits and then
// shifts traffic would shift it to the revision it just replaced.
//
// This port had exactly that defect. It was found by generalising a blocker
// USOSS-12 hit on their own port: an adapter that narrows a response decides
// what the layers above it are able to know. The SDK adapter was keeping the
// counts and discarding the Deployments array, so the question had been asked of
// the service and thrown away.
func TestReadinessIsAboutTheRevisionAskedFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	first, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	ecs.Advance(aws.MemoryCluster, "apphub-billing")
	if _, err := rt.WaitForService(ctx, first.Ref, spec.Replicas, compute.WaitOptions{
		Timeout: time.Second,
	}); err != nil {
		t.Fatalf("waiting for the first rollout: %v", err)
	}

	// A new revision. The previous revision's tasks are still running, so the
	// service-level count is already at the desired number.
	spec.Image = "example-registry/apphub/billing:v2"
	second, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if second.Revision == first.Revision {
		t.Fatal("the revision did not change, so this test cannot distinguish anything")
	}

	// The property: a revision with nothing running is NOT ready, and
	// ReadyReplicas counts only instances of the revision that was asked for.
	if second.Phase == compute.PhaseReady {
		t.Errorf("a deployment where no task of the new revision has started reported %q",
			second.Phase)
	}
	if second.ReadyReplicas != 0 {
		t.Errorf("ReadyReplicas = %d for a revision with nothing running; the previous "+
			"revision's tasks are not serving this spec", second.ReadyReplicas)
	}

	// And a wait must not succeed on the strength of the old revision's tasks.
	if _, err := rt.WaitForService(ctx, second.Ref, spec.Replicas, compute.WaitOptions{
		Timeout: 150 * time.Millisecond,
	}); !errors.Is(err, compute.ErrTimeout) {
		t.Errorf("waiting for a revision that never rolled out returned %v, want ErrTimeout", err)
	}

	// Once the substrate actually starts them, it converges.
	ecs.Advance(aws.MemoryCluster, "apphub-billing")
	got, err := rt.WaitForService(ctx, second.Ref, spec.Replicas, compute.WaitOptions{
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("waiting for a rolled-out revision: %v", err)
	}
	if got.Phase != compute.PhaseReady || got.ReadyReplicas != spec.Replicas {
		t.Errorf("after the rollout: phase %q ready %d, want %q and %d",
			got.Phase, got.ReadyReplicas, compute.PhaseReady, spec.Replicas)
	}
}

// TestAFailedRolloutIsReportedFailedRatherThanPending.
//
// A deployment the substrate has given up on will not converge without a change
// to the spec, so reporting it pending makes every caller wait out its own
// deadline for a state that is never coming — and then report a timeout, which
// says "too slow" for something that had already failed. The substrate's own
// reason is relayed rather than branched on.
func TestAFailedRolloutIsReportedFailedRatherThanPending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	const reason = "ECS deployment circuit breaker: task failed to start"
	ecs.FailRollout(aws.MemoryCluster, "apphub-billing", reason)

	got, err := rt.DescribeService(ctx, st.Ref)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if got.Phase != compute.PhaseFailed {
		t.Errorf("a failed rollout reports phase %q, want %q", got.Phase, compute.PhaseFailed)
	}
	if !strings.Contains(got.Message, reason) {
		t.Errorf("the message %q does not relay the substrate's reason", got.Message)
	}

	// And a wait returns the failure rather than sitting until its deadline.
	_, err = rt.WaitForService(ctx, st.Ref, 1, compute.WaitOptions{Timeout: 5 * time.Second})
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("waiting on a failed rollout returned %v, want ErrFailed", err)
	}
}

// TestAnEnsureAgainstARevokedRoleRefusesAndWritesNothing is the end-to-end half.
//
// It is deliberately NOT presented as a test of the proof-inside-the-write: it
// passes with that proof removed, because the caller's own check catches this
// state and the two are adjacent. Naming it for what it actually covers matters
// — the version of this test that claimed the stronger property was green
// against the defect, which is the same trap USOSS-12 and USOSS-14 each reported
// hitting on their own ports. The stronger property is in
// TestReconcileRolePoliciesProvesOwnershipItself, which is internal because the
// state it needs cannot be reached from outside.
func TestAnEnsureAgainstARevokedRoleRefusesAndWritesNothing(t *testing.T) {

	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	const execRole = "exec-apphub-billing"

	// Somebody removes the ownership marker from the execution role. A caller
	// that checked earlier still believes it owns the role.
	if err := sub.IAM.UntagRole(ctx, execRole, []string{"apphub:component"}); err != nil {
		t.Fatalf("revoking the marker: %v", err)
	}
	before := iam.RolePolicies(execRole)

	// The write must refuse, and must write nothing. The binding is a REAL
	// reference from this provider's own store, resolved through the real
	// resolver: the point of the assertion below is that the secret-read grant
	// was not attached, and a binding that never resolved would satisfy it
	// vacuously.
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  putSecret(t, p, "token", ""),
	}}
	_, err := rt.EnsureService(ctx, spec)
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("an Ensure against a role whose marker was revoked returned %v, want ErrNotOwned",
			err)
	}
	after := iam.RolePolicies(execRole)
	if len(after) != len(before) {
		t.Errorf("the refused write still changed the role's policies: %d before, %d after. A "+
			"refusal that writes first is not a refusal", len(before), len(after))
	}
	if _, planted := after["apphub-secret-read"]; planted {
		t.Error("a secret-read grant was attached to a role this provider no longer owns — the " +
			"exact outcome the proof-at-the-write exists to prevent")
	}
}

// TestAValueTheSubstrateWouldNarrowIsRefused.
//
// Every number this port hands an AWS SDK is an int32, and the interface speaks
// int. A narrowing conversion that is not bounded first does not fail — it
// silently means something else. Port 70000 arrives as 4464, a rule for a port
// the caller never named; a replica count above MaxInt32 arrives negative, which
// ECS reads as "scale to nothing".
//
// The in-memory substrate accepted both, which is the sharper half of the
// problem: **a fake that accepts what the real substrate rejects is a fake that
// certifies invalid input.** So the bound is checked at the port boundary, which
// both substrates go through, rather than in either of them.
//
// Driven over a generated population rather than two chosen values, because the
// interesting cases are the boundaries themselves.
func TestAValueTheSubstrateWouldNarrowIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("ports", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			port  int
			legal bool
		}{
			{0, false}, {-1, false}, {1, true}, {8080, true},
			{65535, true}, {65536, false}, {70000, false}, {1 << 31, false},
		} {
			p, _, spec := serviceFixture(t, nil)
			rt := containers(t, p)
			spec.Ports = []compute.PortSpec{{Number: tc.port}}
			_, err := rt.EnsureService(ctx, spec)
			switch {
			case tc.legal && err != nil:
				t.Errorf("port %d was refused: %v", tc.port, err)
			case !tc.legal && !errors.Is(err, compute.ErrInvalidSpec):
				t.Errorf("port %d returned %v, want ErrInvalidSpec. Unbounded, it narrows to %d "+
					"at the SDK", tc.port, err, int32(tc.port))
			}
		}
	})

	t.Run("replicas", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			replicas int
			legal    bool
		}{
			{0, true}, {1, true}, {-1, false},
			{math.MaxInt32, true}, {math.MaxInt32 + 1, false},
		} {
			p, _, spec := serviceFixture(t, nil)
			rt := containers(t, p)
			spec.Replicas = tc.replicas
			_, err := rt.EnsureService(ctx, spec)
			switch {
			case tc.legal && err != nil:
				t.Errorf("replicas %d was refused: %v", tc.replicas, err)
			case !tc.legal && !errors.Is(err, compute.ErrInvalidSpec):
				t.Errorf("replicas %d returned %v, want ErrInvalidSpec. Unbounded, it narrows to "+
					"%d, which ECS reads as scale-to-nothing", tc.replicas, err, int32(tc.replicas))
			}
		}
	})

	t.Run("ScaleService takes the same bound as the spec", func(t *testing.T) {
		t.Parallel()
		// The same value has to be refused wherever it enters, or the bound is a
		// property of one code path rather than of the provider.
		p, _, spec := serviceFixture(t, nil)
		rt := containers(t, p)
		st, err := rt.EnsureService(ctx, spec)
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if err := rt.ScaleService(ctx, st.Ref, math.MaxInt32+1); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("ScaleService accepted a count EnsureService refuses: %v", err)
		}
	})
}

// stringSurfaces walks a rendered object and returns every string it holds,
// keyed by a dotted path such as "Container.Env[0].Value".
//
// # Why this is derived and not a list
//
// The population it replaces was a hand-written list of five fields — env,
// docker labels, tags, image and log group. That list was a claim about where
// secret material could reach, made by the same person who wrote the code it
// was checking, and it was wrong in a way nobody would have noticed: planting
// the address in Container.Name passed, because nobody had thought to name
// Container.Name. A field added to the task definition tomorrow is unscanned by
// a list and scanned by this.
//
// The instrument's quality and its population's quality are independent, and a
// leak test whose population is hand-chosen can only find leaks into fields
// somebody already suspected.
func stringSurfaces(prefix string, v reflect.Value, out map[string]string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			stringSurfaces(prefix, v.Elem(), out)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			if !t.Field(i).IsExported() {
				// Unreadable through reflection. Recorded rather than passed
				// over, because an unscanned surface that says nothing is the
				// defect this rewrite exists to remove.
				out[prefix+"."+t.Field(i).Name+" (UNEXPORTED, NOT SCANNED)"] = ""
				continue
			}
			stringSurfaces(prefix+"."+t.Field(i).Name, v.Field(i), out)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			stringSurfaces(fmt.Sprintf("%s[%d]", prefix, i), v.Index(i), out)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			// The key is a surface too: a leak into a label NAME is a leak.
			stringSurfaces(fmt.Sprintf("%s[%v](key)", prefix, k), k, out)
			stringSurfaces(fmt.Sprintf("%s[%v]", prefix, k), v.MapIndex(k), out)
		}
	case reflect.String:
		out[prefix] = v.String()
	default:
		// Numbers and bools cannot carry a string sentinel.
	}
}

// TestANonContainerPlacementIsNotRefusedButAHalfConfiguredOneIs pins both sides
// of the construction check, because the rule has been wrong in each direction.
//
// It began as "every placement needs a cluster, subnets and a VPC", on the
// reasoning that a half-configured placement would be accepted at construction
// and refused at deploy, in front of somebody other than the operator who
// mis-configured it. That is still true of a HALF-configured placement.
//
// It was false of a placement with none of them. USOSS-26's secret store keeps
// parameters per region, so a placement can exist solely to hold secrets
// somewhere else and have no ECS cluster at all — a legal configuration this
// provider refused to construct. That is a false refusal, and it is the same
// shape as the port bound that refused a legal ICMP wildcard because it had been
// written to catch a sentinel: a guard aimed at one failure that fires on a
// legitimate case nobody had in view.
//
// Both directions are here because fixing one is how you break the other.
func TestANonContainerPlacementIsNotRefusedButAHalfConfiguredOneIs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pc      aws.PlacementConfig
		wantErr bool
	}{
		{
			name: "a placement with nothing on it hosts no containers and is accepted",
			pc:   aws.PlacementConfig{Region: "another-region"},
		},
		{
			name:    "a cluster with no subnets is half-configured and is refused",
			pc:      aws.PlacementConfig{ClusterARN: "arn:aws:ecs:r:" + aws.MemoryAccount + ":cluster/c"},
			wantErr: true,
		},
		{
			name: "subnets with no cluster are refused too, so the check is not one-sided",
			pc: aws.PlacementConfig{
				Subnets: []string{"subnet-placeholder"}, VPC: "vpc-placeholder",
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := fullConfig()
			cfg.Placements["elsewhere"] = tc.pc
			_, err := aws.New(aws.NewMemorySubstrate(), cfg)
			switch {
			case tc.wantErr && err == nil:
				t.Error("a half-configured placement was accepted at construction; the operator " +
					"who mis-configured it is not the person who would see the deploy fail")
			case !tc.wantErr && err != nil:
				t.Errorf("a placement that hosts no containers was refused at construction: %v. "+
					"A secret store keeps parameters per region, so a placement can legitimately "+
					"exist with no ECS cluster on it", err)
			}
		})
	}
}

// TestTheExecHookCanSayYes is the self-check on
// [aws.Harness.CanExecInto], and the reason the conformance hook it answers is
// worth having.
//
// security/exec-does-not-widen-the-workload-identity SKIPPED for this provider
// until the hook existed, which is an unmeasured security invariant for a
// capability the provider advertises -- it ships CapWorkloadExec with the
// container runtime and the ssmmessages grant with it. A hook fixes the skip and
// introduces a worse failure mode: a hook that always answers false makes the
// check pass without measuring anything, and an inert hook and a correct
// provider are the same silence.
//
// So both directions are pinned. With this provider's real grants the answer is
// NO, which is what the check asserts; with an ecs:ExecuteCommand grant planted
// on the same role the answer is YES, which is what proves the first answer was
// a measurement.
//
// The distinction the hook has to get right is that ECS Exec has two halves
// belonging to different principals. ExecEnabled grants the task role
// ssmmessages:{Create,Open}{Control,Data}Channel so the agent can open its side
// of the channel -- the TARGET half. Opening a session is ecs:ExecuteCommand,
// and it is the operator's. A hook that read the channel grants as "can exec"
// would report true for every exec-enabled workload and turn a correct provider
// red.
func TestTheExecHookCanSayYes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	// Exec ON, so the task role really does hold the ssmmessages grants. The
	// interesting answer is the one given in their presence.
	spec.ExecEnabled = true
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("ensure with ExecEnabled: %v", err)
	}
	role := roleOf(spec.Identity)
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	if _, granted := iam.RolePolicies(role)["apphub-ecs-exec"]; !granted {
		t.Fatal("ExecEnabled did not attach the channel grant, so the case below is not the one " +
			"this test is about")
	}

	can, err := p.Harness().CanExecInto(ctx, spec.Identity, spec.Identity)
	if err != nil {
		t.Fatalf("CanExecInto: %v", err)
	}
	if can {
		t.Error("the hook reports that an exec-ENABLED workload's own identity can open a session " +
			"against it. ExecEnabled is the target half; the ssmmessages channel grants are not " +
			"an opener grant, and reading them as one would turn a correct provider red")
	}

	// And now the grant that genuinely does widen the identity. Planted rather
	// than produced, because this provider does not produce it -- which is the
	// property under test and the reason the hook needs an independent way to
	// come out true.
	for name, doc := range map[string]string{
		"planted-exact":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecs:ExecuteCommand"],"Resource":"*"}]}`,
		"planted-service-wide":  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecs:*","Resource":"*"}]}`,
		"planted-admin":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		"planted-start-session": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:StartSession"],"Resource":"*"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			// Not parallel: these share one substrate and each plants and removes
			// the policy it is about.
			if err := sub.IAM.PutRolePolicy(ctx, role, name, doc); err != nil {
				t.Fatalf("planting %s: %v", name, err)
			}
			defer func() {
				if err := sub.IAM.DeleteRolePolicy(ctx, role, name); err != nil {
					t.Fatalf("removing %s: %v", name, err)
				}
			}()
			can, err := p.Harness().CanExecInto(ctx, spec.Identity, spec.Identity)
			if err != nil {
				t.Fatalf("CanExecInto: %v", err)
			}
			if !can {
				t.Errorf("the hook reports NO against %s. A hook that cannot come out true makes "+
					"security/exec-does-not-widen-the-workload-identity pass without measuring "+
					"anything", doc)
			}
		})
	}

	// A Deny is not a grant. Without this the wildcard cases above would pass
	// against a hook that ignored Effect, which is the one field that inverts
	// the answer.
	if err := sub.IAM.PutRolePolicy(ctx, role, "planted-deny",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`); err != nil {
		t.Fatalf("planting the deny: %v", err)
	}
	if can, err := p.Harness().CanExecInto(ctx, spec.Identity, spec.Identity); err != nil {
		t.Fatalf("CanExecInto: %v", err)
	} else if can {
		t.Error("a Deny statement was read as a grant")
	}
}

// --- version pins ------------------------------------------------------------

// TestAVersionPinReachesTheTaskDefinitionAndNotTheGrant is the end-to-end pin,
// and the two halves have to go to DIFFERENT places.
//
// This is the defect that turned main red when #22 and #23 met: USOSS-35 added
// [compute.SecretBinding.Version] and taught the SSM store to honour it, and
// the container port's own seam type dropped it — so the port resolved every
// binding unpinned, accepted a pin to a revision that did not exist, and
// rendered a pinned and an unpinned binding to one secret identically. A caller
// believed it had pinned a revision and the workload followed the latest value.
//
// The asymmetry is the part worth pinning here rather than in the store's tests:
//
//   - The ECS `valueFrom` MUST carry the selector, because that string is what
//     resolves the parameter at launch and it is the only place a caller can
//     confirm which revision the workload was wired to.
//   - The IAM grant MUST NOT, because an IAM Resource element has no version
//     component at all. A grant naming "…:parameter/x:3" authorises nothing,
//     and the failure surfaces as a task that will not start — minutes later,
//     as a launch failure rather than as the spec error it would have been.
//
// The store establishes that split ([SecretParameterRef.baseARN]); this port is
// the thing that attaches the grant, so this is where getting it backwards would
// actually bite.
func TestAVersionPinReachesTheTaskDefinitionAndNotTheGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)

	// Two writes, so there is a revision to pin that is NOT the current one.
	// Pinning the latest revision would pass against a provider that ignored
	// the field entirely.
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("acquiring the secret store: %v", err)
	}
	put := func(value string) compute.StoredSecret {
		stored, err := store.Put(ctx, compute.SecretSpec{
			Name: "db-password", Scope: "billing", Value: compute.NewSecretValue(value),
		})
		if err != nil {
			t.Fatalf("storing: %v", err)
		}
		return stored
	}
	first := put("value-one")
	second := put("value-two")
	if first.Version == "" || first.Version == second.Version {
		t.Fatalf("the store reported versions %q and %q for two distinct writes; this test needs "+
			"two revisions to tell a pin from a fallback", first.Version, second.Version)
	}

	spec.Secrets = []compute.SecretBinding{{
		EnvName: "DATABASE_PASSWORD",
		Secret:  first.Ref,
		Version: first.Version,
	}}
	if _, err := rt.EnsureService(ctx, spec); err != nil {
		t.Fatalf("ensure with a pinned binding: %v", err)
	}

	meta, err := sub.Parameters.Describe(ctx, paramOf(t, first.Ref))
	if err != nil {
		t.Fatalf("describing the parameter: %v", err)
	}
	wantValueFrom := meta.ARN + ":" + first.Version

	ecs, ok := sub.ECS.(*aws.MemoryECS)
	if !ok {
		t.Fatal("expected the in-memory ECS substrate")
	}
	defs := ecs.Definitions()
	if len(defs) != 1 {
		t.Fatalf("expected one task definition, got %d", len(defs))
	}
	secrets := defs[0].Container.Secrets
	if len(secrets) != 1 {
		t.Fatalf("the task definition carries %d secret reference(s), want 1", len(secrets))
	}
	if secrets[0].ValueFrom != wantValueFrom {
		t.Errorf("the task definition references %q, want %q. Without the selector the workload "+
			"resolves the LATEST revision, which is the silent unpinning the field exists to close",
			secrets[0].ValueFrom, wantValueFrom)
	}

	// And the grant names the parameter, not the revision.
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	doc, granted := iam.RolePolicies("exec-apphub-billing")["apphub-secret-read"]
	if !granted {
		t.Fatal("no secret-read grant was attached, so the reference the task holds is unreadable")
	}
	if !strings.Contains(doc, meta.ARN) {
		t.Errorf("the secret-read grant does not name %s: %s", meta.ARN, doc)
	}
	if strings.Contains(doc, wantValueFrom) {
		t.Errorf("the secret-read grant names the VERSIONED ARN %s. An IAM Resource element has "+
			"no version component, so this grant authorises nothing and the task would fail to "+
			"start: %s", wantValueFrom, doc)
	}
}

// TestEnsureRefusesAPinToARevisionThatDoesNotExist is the other half of the
// invariant, and it is the half a fallback would quietly satisfy.
//
// A provider that resolved an unknown revision by handing back the current value
// would deploy a workload the caller believes is pinned to something else. That
// is worse than a refusal in the only way that matters: it is not observable.
//
// It is NOT a duplicate of the store's TestPinToARevisionThatDoesNotExistIsRefused
// (USOSS-35), which drives the same refusal through Provider.SecretParameterARNs
// and enumerates the malformed-version cases more thoroughly. The store already
// refused; what accepted the unknown revision was THIS port, because its seam
// type dropped the field before the store ever saw it. So the layer is the
// point: the assertion is that an EnsureService refuses, and that it refuses
// before writing anything.
func TestEnsureRefusesAPinToARevisionThatDoesNotExist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	rt := containers(t, p)
	ref := putSecret(t, p, "token", "")

	for name, version := range map[string]string{
		"a revision beyond the ones that exist": "99",
		"not a revision at all":                 "1-no-such-revision",
	} {
		t.Run(name, func(t *testing.T) {
			s := spec
			s.Secrets = []compute.SecretBinding{{
				EnvName: "TOKEN", Secret: ref, Version: version,
			}}
			if _, err := rt.EnsureService(ctx, s); err == nil {
				t.Fatalf("a binding pinned to %q was accepted", version)
			}
		})
	}

	// Nothing was written on the way to either refusal — the pin is validated
	// before the ownership check, so this is the same ordering property
	// [TestARefusedEnsureWritesNothing] pins for a foreign service.
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	if got := iam.RolePolicies("exec-apphub-billing"); len(got) != 0 {
		t.Errorf("a refused pin still attached %v to an execution role", got)
	}
}

// TestAResolverThatDropsAPinIsRefused seals the seam.
//
// [SecretResolver] is caller-supplied, so a resolver that accepted a pinned
// binding and returned an unpinned address would make this port silently unpin
// every workload it resolved — and the port would report success. A resolver
// that cannot pin is entitled to say so with
// [compute.ErrVersionPinningUnsupported]; one that reports success for work it
// did not do is a fail-open, and the port refuses it rather than trusting the
// contract.
//
// It is the same reasoning as the foreign-provider, wrong-kind and placement
// checks: the port's fail-closed behaviour must not be a property of whichever
// resolver it was handed.
func TestAResolverThatDropsAPinIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{dropsVersion: true}
	})
	rt := containers(t, p)
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "parameter/token"},
		Version: "3",
	}}
	_, err := rt.EnsureService(ctx, spec)
	if err == nil {
		t.Fatal("a resolver that discarded the pin was accepted; the workload would follow the " +
			"latest value while the caller believed it was pinned")
	}
	if !strings.Contains(err.Error(), "no revision") {
		t.Errorf("the refusal does not say the address came back unpinned: %v", err)
	}

	// The same resolver honouring the pin is accepted, so the test above is a
	// refusal of the DROPPED pin and not of pinning in general.
	p2, _, spec2 := serviceFixture(t, func(cfg *aws.Config) {
		cfg.Container.Secrets = stubSecrets{}
	})
	spec2.Secrets = spec.Secrets
	if _, err := containers(t, p2).EnsureService(ctx, spec2); err != nil {
		t.Errorf("an honoured pin through the same stub was refused: %v", err)
	}
}
