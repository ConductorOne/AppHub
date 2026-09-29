// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// functionRuntime implements [compute.FunctionRuntime] with Lambda for the
// function half and ELBv2 for the endpoint half (endpoint.go).
//
// It is the source system's LambdaDeployModule (lambda.go) with the deploy
// orchestration, the progress reporting and the application record removed —
// those belong to a deploy layer, not to a compute provider — and with six of
// its behaviours deliberately not reproduced. Each is called out at the call
// site; collected here because they are one class:
//
//   - **A failed read is not evidence of absence.** The source treats *any*
//     error from GetFunction as "the function does not exist" and creates
//     (lambda.go:195-204), and does the same with GetRole (lambda.go:938-948).
//     A throttle or an authorization failure therefore becomes a create. Here
//     only [ErrNoSuchResource] means absent and everything else is returned.
//   - **An adopted resource is checked first.** The source writes an ownership
//     tag on the load balancer and the target group and never reads one, and
//     writes none at all on the function.
//   - **A failure is not a warning.** Six steps on this path log a warning and
//     continue: the invoke grant (lambda.go:461-467), each listener
//     (lambda.go:485-495), the load balancer wait (lambda.go:499-503), the
//     ingress authorisation (lambda.go:588-590), the execution policy
//     attachment (lambda.go:970-976) and the artefact save (lambda.go:296-300).
//     Every one of them produces a deployment that reports success and does not
//     work.
//   - **Nothing is inferred that the caller can state.** The source substitutes
//     a runtime for an empty one (lambda.go:84-87), derives a handler from the
//     runtime and defaults it to a Node.js handler for a runtime it does not
//     recognise (lambda.go:920-931), and synthesises a placeholder bundle when
//     no code was supplied (lambda.go:875-916).
//   - **A missing configuration value never widens a boundary.** See
//     [Provider.ingressRules] and [PlacementConfig.Certificates].
//   - **Nothing blocks inside Ensure.** The source waits inline, twice for the
//     function (lambda.go:242-245, :272-277) and once for the load balancer
//     (lambda.go:497-503), with hardcoded deadlines. [compute.Status] says why
//     that is a conformance failure rather than a style difference.
//
// # What Lambda cannot report back, and what that costs
//
// A read-back reconstructs the effective spec from the function itself — Lambda
// for the configuration, its tags for the caller's labels and for the two
// references ([tagIdentity], [tagPlacement]). Nothing is remembered in process,
// so a Describe reports what AWS has rather than what the last Ensure believed
// it wrote.
//
// The exception is [compute.FunctionSpec.Code]. Lambda does not hand a bundle
// back — it reports a digest and a size — so the effective spec's Code is the
// zero value and [compute.FunctionStatus.Revision] is the observable identity of
// what is deployed. That is stated here rather than hidden because
// [compute.Status] requires the effective spec to be populated, and a reader
// comparing one field of it against what they passed in deserves to know which
// field cannot be compared.
type functionRuntime struct{ p *Provider }

var _ compute.FunctionRuntime = (*functionRuntime)(nil)

// Lambda's own limits on a function, as [compute.ErrInvalidSpec] rather than as
// an API error from the middle of a deploy.
const (
	minFunctionMemoryMiB = 128
	maxFunctionMemoryMiB = 10240
	maxFunctionTimeout   = 900 * time.Second
)

// The architecture names Lambda uses. The interface's vocabulary is
// [compute.Architecture]; these are the substrate's, and the mapping is here
// and nowhere else.
const (
	lambdaArchARM64 = "arm64"
	lambdaArchAMD64 = "x86_64"
)

func lambdaArchitecture(a compute.Architecture) (string, error) {
	switch a {
	case compute.ArchARM64:
		return lambdaArchARM64, nil
	case compute.ArchAMD64:
		return lambdaArchAMD64, nil
	default:
		return "", fmt.Errorf("%w: %q is not an architecture this interface defines",
			compute.ErrInvalidSpec, a)
	}
}

func computeArchitecture(a string) compute.Architecture {
	switch a {
	case lambdaArchARM64:
		return compute.ArchARM64
	case lambdaArchAMD64:
		return compute.ArchAMD64
	default:
		return ""
	}
}

// EnsureFunction creates or converges a function.
//
// # Why this can need two calls, and why it says so instead of blocking
//
// Lambda mutates a function's configuration and its code through two API calls
// and refuses the second while the first is still in flight. The source system's
// answer is to block in between (lambda.go:242-245), which
// [compute.Status] rules out: an asynchronous port's Ensure must return promptly
// so that a caller chooses its own deadline and can provision two things at
// once.
//
// So this does what it can without blocking, and is honest about the rest:
//
//   - A function that does not exist is created, with its configuration and its
//     code in one call. No conflict is possible, and this is the ordinary first
//     deploy.
//   - A function whose configuration changed and whose code did not gets one
//     mutation. This is the ordinary redeploy of unchanged code.
//   - A function whose code changed and whose configuration did not gets one
//     mutation.
//   - A function where **both** changed gets the configuration update, and then
//     the code update fails as [ErrConflict], which
//     [Provider.substrateError] maps to [compute.ErrTransient]. The caller's
//     retry finds the configuration converged and applies the code alone.
//
// The last case is the interesting one and the ordering in it is deliberate.
// Configuration carries the execution role, so applying configuration first
// means new code never runs under an old role; the other order can. Two Ensures
// is the honest cost of a substrate that serialises the two halves, and
// [compute.ErrTransient] means precisely "retry", which is the correct
// instruction. What this must not do is block, and it must not report success
// with half the spec applied — so the caller is told.
//
// The in-memory substrate reproduces the conflict rather than describing it, so
// the path above is exercised by a test and not only by this comment.
func (f *functionRuntime) EnsureFunction(ctx context.Context, spec compute.FunctionSpec) (*compute.FunctionStatus, error) {
	req, err := f.p.functionRequest(ctx, spec)
	if err != nil {
		return nil, err
	}

	current, err := f.p.sub.Lambda.GetFunction(ctx, req.name)
	switch {
	case err == nil:
		if err := checkOwned(current.Tags, "Lambda function", componentFunction, req.name); err != nil {
			return nil, err
		}
		current, err = f.p.convergeFunction(ctx, current, req)
		if err != nil {
			return nil, err
		}
	case errors.Is(err, ErrNoSuchResource):
		current, err = f.p.sub.Lambda.CreateFunction(ctx, CreateFunctionRequest{
			Name:           req.name,
			Runtime:        req.effective.Runtime,
			Handler:        req.effective.Handler,
			RoleARN:        req.roleARN,
			MemoryMiB:      req.effective.Resources.MemoryMiB,
			TimeoutSeconds: int(req.effective.Timeout.Seconds()),
			Architecture:   req.architecture,
			Env:            req.env,
			Code:           req.code,
			Description:    f.p.cfg.Function.description(),
			Tags:           req.tags,
		})
		if err != nil {
			return nil, f.p.substrateError(err)
		}
	default:
		// Not "the function does not exist". See [functionRuntime].
		return nil, f.p.substrateError(err)
	}
	return f.p.functionStatus(current), nil
}

// functionRequest is a validated spec, resolved against configuration and the
// substrate, ready to hand to Lambda.
type functionRequest struct {
	name         string
	roleARN      string
	architecture string
	env          map[string]string
	code         FunctionCode
	tags         map[string]string
	effective    compute.FunctionSpec
}

// functionRequest validates and resolves. Every refusal names the field.
func (p *Provider) functionRequest(ctx context.Context, spec compute.FunctionSpec) (functionRequest, error) {
	var out functionRequest
	if err := validateName(spec.Name); err != nil {
		return out, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return out, err
	}
	pc, err := p.regionalPlacement(spec.Placement)
	if err != nil {
		return out, err
	}
	if !p.cfg.Function.allowsRuntime(spec.Runtime) {
		return out, fmt.Errorf("%w: runtime %q is not one this provider offers; the runtimes "+
			"configured here are %v. Substituting a different one would run the caller's bundle "+
			"under an interpreter it was not built for, and the source system's substitution of a "+
			"default for an empty runtime is exactly that",
			compute.ErrInvalidSpec, spec.Runtime, p.cfg.Function.runtimes())
	}
	if strings.TrimSpace(spec.Handler) == "" {
		// Not derived from the runtime. The source system derives it and falls
		// back to a Node.js handler for a runtime it does not recognise
		// (lambda.go:920-931), so a Go bundle deploys with a handler naming a
		// JavaScript symbol and fails at the first invocation.
		return out, fmt.Errorf("%w: a function needs a handler; this provider will not derive one "+
			"from the runtime, because a wrong handler deploys successfully and fails at the first "+
			"invocation", compute.ErrInvalidSpec)
	}
	switch {
	case spec.Resources.MemoryMiB < minFunctionMemoryMiB || spec.Resources.MemoryMiB > maxFunctionMemoryMiB:
		return out, fmt.Errorf("%w: a function's memory allocation must be between %d and %d MiB "+
			"and this spec asks for %d", compute.ErrInvalidSpec,
			minFunctionMemoryMiB, maxFunctionMemoryMiB, spec.Resources.MemoryMiB)
	case spec.Resources.CPUMillicores != 0:
		// [compute.Resources.CPUMillicores] documents zero as "derive it", and
		// Lambda is the substrate that genuinely does — it is the reason the
		// field reads that way. It has no way to honour an explicit request, and
		// accepting one silently would hand the caller a function with a
		// different capacity from the one it asked for.
		return out, fmt.Errorf("%w: this provider derives CPU from memory and cannot honour an "+
			"explicit allocation of %d millicores; leave Resources.CPUMillicores at zero, which "+
			"the interface defines as \"derive it\"",
			compute.ErrInvalidSpec, spec.Resources.CPUMillicores)
	}
	switch {
	case spec.Timeout <= 0:
		return out, fmt.Errorf("%w: a function needs a positive invocation timeout",
			compute.ErrInvalidSpec)
	case spec.Timeout > maxFunctionTimeout:
		return out, fmt.Errorf("%w: this substrate bounds an invocation at %s and this spec asks "+
			"for %s", compute.ErrInvalidSpec, maxFunctionTimeout, spec.Timeout)
	case spec.Timeout%time.Second != 0:
		// Refused rather than rounded, which is the same call three sibling
		// ports made for the same reason. Rounding down can reach a timeout
		// shorter than the caller asked for and rounding up silently bills for
		// longer; either way the deployed function does not do what the spec
		// says.
		return out, fmt.Errorf("%w: this substrate expresses an invocation timeout in whole "+
			"seconds and %s is not one; this provider refuses rather than rounding, because a "+
			"rounded timeout is a different timeout", compute.ErrInvalidSpec, spec.Timeout)
	}
	if len(spec.Ingress) > 0 {
		// [compute.FunctionSpec.Ingress] says empty is the right answer on
		// Lambda, which has no inbound network surface at all: a function is
		// invoked through the control plane. Accepting a rule set would report a
		// reachability restriction this provider did not apply — the same
		// failure as accepting a peer it cannot resolve, one layer up.
		return out, fmt.Errorf("%w: a Lambda function has no inbound network surface for an "+
			"ingress rule to restrict — it is invoked through the control plane — so this "+
			"provider refuses a rule set rather than accepting one it cannot apply. Reachability "+
			"for the endpoint in front of it is EndpointSpec.Ingress", compute.ErrInvalidSpec)
	}
	if len(spec.Secrets) > 0 {
		// [compute.SecretBinding] is explicit that the value is never read by
		// apphub at deploy time: the provider hands the runtime a reference and
		// the runtime resolves it at launch. Lambda has no such mechanism — a
		// function's environment holds literal values — so honouring a binding
		// would mean reading the material and writing it into durable function
		// configuration visible to anyone with lambda:GetFunction. That is the
		// property the type exists to protect, so this refuses.
		//
		// ErrInvalidSpec, not ErrUnsupported naming CapSecretStore: this provider
		// advertises CapSecretStore whenever Config.Secrets is configured
		// (USOSS-26), so the refusal is not "this provider has no secret store" --
		// it does, and Capabilities() says so. It is "this field, on this
		// resource, cannot be honoured by any provider whose runtime resolves
		// secrets by writing literal environment values", which is a property of
		// the spec and the substrate together and not of a missing capability. A
		// caller that checked Capabilities() first and saw CapSecretStore true
		// would otherwise be told two contradictory things by the same provider.
		return out, fmt.Errorf("%w: Lambda resolves no secret reference at launch: a function's "+
			"environment holds literal values, so honouring a SecretBinding would mean this "+
			"provider reading the material and writing it into durable function configuration. A "+
			"function that needs a secret reads it at runtime under its own workload identity",
			compute.ErrInvalidSpec)
	}
	if err := p.validateWorkloadCapabilities(spec.Capabilities); err != nil {
		return out, err
	}

	arch := spec.Architecture
	if arch == "" {
		arch = p.cfg.Function.defaultArchitecture()
	}
	if out.architecture, err = lambdaArchitecture(arch); err != nil {
		return out, err
	}
	if out.name, err = p.functionName(spec.Name); err != nil {
		return out, err
	}
	if out.code, err = p.resolveCode(ctx, spec.Code); err != nil {
		return out, err
	}
	roleName, roleARN, err := p.resolveExecutionRole(ctx, spec.Identity)
	if err != nil {
		return out, err
	}
	out.roleARN = roleARN
	if out.env, err = environment(spec.Env); err != nil {
		return out, err
	}

	out.effective = spec
	out.effective.Placement = compute.Placement{Name: pc.Name}
	out.effective.Architecture = arch
	out.tags = ownershipTags(out.name, componentFunction, spec.Labels)
	out.tags[tagPlacement] = pc.Name
	out.tags[tagIdentity] = roleName
	return out, nil
}

// regionalPlacement resolves a placement and refuses one this provider instance
// cannot serve.
//
// The refusal is the ruling that placement on AWS is *refused* when it cannot be
// honoured, never ignored. [compute.WorkloadIdentitySpec.Placement] says an AWS
// provider "can ignore" placement because an IAM role is account-global, and
// that reading is wrong for anything regional: a caller naming a placement whose
// region differs from the one this provider's clients address would get a
// resource in a region it did not choose, and would have no way to find out.
// [PlacementConfig.Region] exists precisely so a placement can differ in region,
// so the mismatch is reachable through ordinary configuration.
//
// A second region is a second provider instance, which is what
// [compute.Placement]'s own documentation proposes: "if that changes, the answer
// is more named placements, not network fields here" — and, one level out, more
// providers.
func (p *Provider) regionalPlacement(placement compute.Placement) (PlacementConfig, error) {
	pc, err := p.cfg.placement(placement)
	if err != nil {
		return PlacementConfig{}, err
	}
	if pc.Region != p.cfg.Region {
		return PlacementConfig{}, fmt.Errorf("%w: placement %q is in region %q and this provider's "+
			"clients address %q. Refusing rather than using the configured region: a caller that "+
			"named a placement and silently got a resource somewhere else has been handed "+
			"something it did not ask for. Construct a second provider for that region",
			compute.ErrInvalidSpec, pc.Name, pc.Region, p.cfg.Region)
	}
	return pc, nil
}

// resolveExecutionRole turns the spec's identity reference into the role ARN
// Lambda needs, and refuses a role Lambda could not assume.
//
// The trust-policy check is the substantive addition. An AWS role trusted by
// ecs-tasks.amazonaws.com cannot be assumed by Lambda —
// [compute.WorkloadIdentitySpec.RunsOn] exists for exactly this substrate — and
// without the check a caller who reused a container identity gets a function
// that creates successfully and cannot start, reported by Lambda as an
// InvalidParameterValueException about a role it cannot assume.
//
// The ownership check is the same one [identityService] runs, on the same two
// tags, because a role is account-global: pointing a function at a role apphub
// created as something else would be using a trust relationship for a purpose
// nobody granted it.
func (p *Provider) resolveExecutionRole(ctx context.Context, ref compute.Ref) (name, arn string, err error) {
	if ref == (compute.Ref{}) {
		return "", "", fmt.Errorf("%w: a function needs a workload identity to run as; "+
			"FunctionSpec.Identity is required", compute.ErrInvalidSpec)
	}
	name, err = p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return "", "", err
	}
	role, err := p.sub.IAM.GetRole(ctx, name)
	if err != nil {
		return "", "", p.substrateError(err)
	}
	if err := checkOwned(role.Tags, "IAM role", componentIdentity, name); err != nil {
		return "", "", err
	}
	if got := runtimeFromTrustPolicy(role.AssumeRolePolicy); got != compute.RuntimeFunction {
		return "", "", fmt.Errorf("%w: %s is trusted by %q rather than by %q, so Lambda cannot "+
			"assume it; ensure the identity with WorkloadIdentitySpec.RunsOn set to %q",
			compute.ErrInvalidSpec, ref, got, compute.RuntimeFunction, compute.RuntimeFunction)
	}
	if role.ARN == "" {
		return "", "", fmt.Errorf("%w: IAM reported no ARN for role %q, and a function's execution "+
			"role is named to Lambda by ARN", compute.ErrFailed, name)
	}
	return name, role.ARN, nil
}

// resolveCode turns a [compute.CodeSource] into the bundle reference Lambda
// takes.
//
// The object path resolves the bucket **through [compute.ObjectStore]** rather
// than by taking the reference apart. [compute.Ref] says a caller must never
// parse an ID and the rule holds inside the package too: the object-store port
// owns its own reference format, it distinguishes three kinds of bucket that
// share [compute.KindBucket], and a general-purpose bucket's name and a table
// bucket's name are derived identically from one logical name. Parsing would
// therefore hand Lambda a bucket name that exists in a different service.
//
// Going through the port also means the bucket is confirmed to exist and to be
// owned by this platform before a function is pointed at it, and it means this
// code needs no change when that port lands: a provider with no object store
// configured refuses here through the interface's own mechanism rather than
// through a special case that somebody would have to remember to remove.
func (p *Provider) resolveCode(ctx context.Context, src compute.CodeSource) (FunctionCode, error) {
	switch {
	case len(src.Inline) > 0 && src.Object != nil:
		return FunctionCode{}, fmt.Errorf("%w: CodeSource carries both an inline bundle and an "+
			"object location, and exactly one is allowed", compute.ErrInvalidSpec)
	case len(src.Inline) > 0:
		if limit := p.cfg.Function.maxInlineBytes(); int64(len(src.Inline)) > limit {
			// Named, not truncated. A truncated zip is not a smaller deployment,
			// it is a corrupt one, and Lambda would report it as a runtime error
			// in a function that deployed successfully.
			return FunctionCode{}, fmt.Errorf("%w: the inline bundle is %d bytes and this "+
				"provider accepts at most %d; a larger bundle goes through an object store",
				compute.ErrInvalidSpec, len(src.Inline), limit)
		}
		// Copied. The caller keeps its slice and this provider must not be
		// holding a window onto storage the caller can still write.
		zip := make([]byte, len(src.Inline))
		copy(zip, src.Inline)
		return FunctionCode{Zip: zip}, nil
	case src.Object != nil:
		key, err := validateObjectKey(src.Object.Key)
		if err != nil {
			return FunctionCode{}, err
		}
		store, err := p.ObjectStores()
		if err != nil {
			return FunctionCode{}, fmt.Errorf("this function's code is in an object store and "+
				"this provider has none: %w", err)
		}
		bucket, err := store.DescribeBucket(ctx, src.Object.Bucket)
		if err != nil {
			return FunctionCode{}, fmt.Errorf("resolving the bundle's bucket: %w", err)
		}
		return FunctionCode{Bucket: bucket.Name, Key: key}, nil
	default:
		// No placeholder bundle. The source system synthesises one
		// (lambda.go:875-916), which deploys a function that answers every
		// request with a fixed string — indistinguishable, from outside, from
		// an application that deployed and is broken.
		return FunctionCode{}, fmt.Errorf("%w: CodeSource is empty; this provider will not "+
			"synthesise a placeholder bundle, because a function serving a placeholder is "+
			"indistinguishable from a deployed application that does not work",
			compute.ErrInvalidSpec)
	}
}

// validateObjectKey enforces the confinement obligation
// [compute.ObjectLocation.Key] states: the provider must reject a key that
// traverses outside the bucket namespace.
//
// It validates the **raw** key rather than a cleaned one, and that is the whole
// design. Cleaning first and then checking is checking a different string from
// the one that reaches the service: path.Clean turns "a/../../b" into "../b", so
// a prefix check on the cleaned form passes for a key whose raw form escapes.
// The rule here is therefore "reject anything that could be traversal",
// evaluated on the bytes the caller supplied.
//
// This is the only path-confinement surface in this port and it has no sibling
// to be consistent with; the object-store port has no data-plane surface at all,
// so the key never reaches it.
func validateObjectKey(key string) (string, error) {
	refuse := func(why string) (string, error) {
		return "", fmt.Errorf("%w: the object key %q %s", compute.ErrInvalidSpec, key, why)
	}
	switch {
	case key == "":
		return refuse("is empty")
	case strings.HasPrefix(key, "/"):
		return refuse("is absolute, which addresses nothing inside a bucket")
	case strings.ContainsAny(key, "\x00\\"):
		return refuse("contains a NUL or a backslash, either of which makes the key that reaches " +
			"the service a different string from the one written here")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return refuse("contains a parent-directory segment")
		}
	}
	if path.Clean(key) != key {
		// Everything the two rules above did not name: an empty segment, a "."
		// segment, a trailing slash. Refused rather than normalised, so that the
		// key this provider hands the service is byte-for-byte the one the
		// caller wrote and there is no second form to reason about.
		return refuse("is not in canonical form; this provider passes a key through unchanged " +
			"rather than normalising it, so that the key it hands the service is the one written here")
	}
	return key, nil
}

// validateWorkloadCapabilities refuses a [compute.WorkloadCapability] this
// provider cannot grant, and an unrecognised one outright.
//
// Enumerated against [compute.WorkloadCapabilities] rather than switched on, so
// that a capability added to the interface later is refused by default instead
// of being silently accepted and never granted -- the same shape
// compute/k8s's container port uses.
//
// [compute.WorkloadCapability.Requires] documents an unrecognised value as
// resolving to the empty [compute.Capability], "which a provider must treat as
// [compute.ErrInvalidSpec] rather than as 'no requirement'" (compute/identity.go).
// Reaching [p.unsupported] directly and naming a fixed capability -- as an
// earlier revision did -- violated that for two reasons at once: a fabricated
// value was reported as ErrUnsupported rather than ErrInvalidSpec, and named
// CapModelInference regardless of what the caller actually asked for.
func (p *Provider) validateWorkloadCapabilities(want []compute.WorkloadCapability) error {
	required := map[compute.WorkloadCapability]compute.Capability{
		compute.WorkloadCapabilityModelInference: compute.CapModelInference,
	}
	for _, wc := range want {
		need, known := required[wc]
		if !known {
			return fmt.Errorf("%w: workload capability %q is not one this interface defines (%v)",
				compute.ErrInvalidSpec, wc, compute.WorkloadCapabilities())
		}
		if !p.caps.Has(need) {
			// Platform grants are permissions on the workload's identity, and a
			// role this package creates carries a trust policy and nothing else
			// by design. The ports that attach a policy own detaching it, because
			// Ensure is declarative, and this port attaches none.
			return p.unsupported(need, fmt.Sprintf("a function asked for %q; this port grants no "+
				"platform capability to a function's identity -- a role this package creates "+
				"carries a trust policy and tags and nothing else, and a port that attaches a "+
				"policy owns detaching it", wc))
		}
	}
	return nil
}

// environment copies the spec's environment into the map Lambda takes, refusing
// a duplicate rather than letting the last one win.
//
// Two [compute.EnvVar] entries naming the same variable are ambiguous input: a
// caller cannot tell from the effective spec which value actually reached the
// function, since a map has one slot per name and the second write is invisible
// once made. [listeners] refuses the analogous case for a duplicate port for
// the same reason -- see endpoint.go -- and this is that refusal for the
// function's environment.
func environment(vars []compute.EnvVar) (map[string]string, error) {
	if len(vars) == 0 {
		return map[string]string{}, nil
	}
	out := make(map[string]string, len(vars))
	for _, v := range vars {
		if _, ok := out[v.Name]; ok {
			return nil, fmt.Errorf("%w: environment variable %q is set more than once; this "+
				"provider refuses rather than letting the last one win, because the effective spec "+
				"could not otherwise say which value actually reached the function",
				compute.ErrInvalidSpec, v.Name)
		}
		out[v.Name] = v.Value
	}
	return out, nil
}

// convergeFunction brings an existing function onto req.
func (p *Provider) convergeFunction(ctx context.Context, current *FunctionRecord, req functionRequest) (*FunctionRecord, error) {
	cfgChanged := current.Runtime != req.effective.Runtime ||
		current.Handler != req.effective.Handler ||
		current.RoleARN != req.roleARN ||
		current.MemoryMiB != req.effective.Resources.MemoryMiB ||
		current.TimeoutSeconds != int(req.effective.Timeout.Seconds()) ||
		!sameEnv(current.Env, req.env)

	if cfgChanged {
		updated, err := p.sub.Lambda.UpdateFunctionConfiguration(ctx, UpdateFunctionConfigurationRequest{
			Name:           req.name,
			Runtime:        req.effective.Runtime,
			Handler:        req.effective.Handler,
			RoleARN:        req.roleARN,
			MemoryMiB:      req.effective.Resources.MemoryMiB,
			TimeoutSeconds: int(req.effective.Timeout.Seconds()),
			Env:            req.env,
			Description:    p.cfg.Function.description(),
		})
		if err != nil {
			return nil, p.substrateError(err)
		}
		current = updated
	}

	// The architecture is a property of the code, not of the configuration:
	// Lambda takes it on CreateFunction and on UpdateFunctionCode and nowhere
	// else, which is why the source system passes it to both (lambda.go:210,
	// :251) and not to UpdateFunctionConfiguration.
	if codeChanged(current, req) {
		updated, err := p.sub.Lambda.UpdateFunctionCode(ctx, req.name, req.architecture, req.code)
		if err != nil {
			if errors.Is(err, ErrConflict) && cfgChanged {
				// Say what happened, because the caller has to know the retry is
				// finishing a half-applied spec rather than starting again. See
				// [functionRuntime.EnsureFunction].
				return nil, fmt.Errorf("%w: the configuration update was applied and Lambda will "+
					"not accept a code update until it settles; re-Ensure this spec to finish it: %w",
					compute.ErrTransient, err)
			}
			return nil, p.substrateError(err)
		}
		current = updated
	}

	put, remove := tagDelta(current.Tags, req.tags)
	if len(remove) > 0 {
		if err := p.sub.Lambda.UntagResource(ctx, current.ARN, remove); err != nil {
			return nil, p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := p.sub.Lambda.TagResource(ctx, current.ARN, put); err != nil {
			return nil, p.substrateError(err)
		}
	}
	// Read back rather than patched in memory: the tags are part of the
	// effective spec and the substrate is the authority on them.
	current, err := p.sub.Lambda.GetFunction(ctx, req.name)
	if err != nil {
		return nil, p.substrateError(err)
	}
	return current, nil
}

// codeChanged decides whether the bundle has to be re-uploaded.
//
// For an inline bundle the answer is exact: Lambda reports the deployed bundle's
// digest and this compares it, so an unchanged bundle costs no mutation — which
// is what keeps the ordinary redeploy of unchanged code down to one call and
// out of the conflict path described on [functionRuntime.EnsureFunction].
//
// For an object bundle the answer is always yes, and it has to be. The caller's
// deploy flow is to upload a new archive to the same key, so the location is
// unchanged in exactly the case where the code changed. Comparing locations
// would skip the update precisely when it was needed. This costs one mutation
// per Ensure on that path and it is the safe direction to be wrong in.
func codeChanged(current *FunctionRecord, req functionRequest) bool {
	if req.code.Zip == nil {
		return true
	}
	return current.CodeDigest != codeDigest(req.code.Zip)
}

// codeDigest renders a bundle's digest the way Lambda reports one: the SHA-256
// of the archive, base64-encoded. Matching Lambda's own encoding is what lets
// the comparison above be a comparison rather than a heuristic.
func codeDigest(zip []byte) string {
	sum := sha256.Sum256(zip)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func sameEnv(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if other, ok := b[k]; !ok || other != v {
			return false
		}
	}
	return true
}

// DescribeFunction reads a function back through the interface.
func (f *functionRuntime) DescribeFunction(ctx context.Context, ref compute.Ref) (*compute.FunctionStatus, error) {
	name, err := f.p.resolve(ref, compute.KindFunction)
	if err != nil {
		return nil, err
	}
	rec, err := f.p.sub.Lambda.GetFunction(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		// [compute.PhaseGone] rather than an error, so teardown and
		// reconciliation are re-runnable without distinguishing "deleted" from
		// "never existed".
		return &compute.FunctionStatus{Status: compute.Status{
			Ref: ref, Phase: compute.PhaseGone, UpdatedAt: time.Now().UTC(),
		}}, nil
	}
	if err != nil {
		return nil, f.p.substrateError(err)
	}
	// A Ref that was valid once is not a capability: the function behind it can
	// have been deleted and a same-named one created by somebody else, so
	// ownership is re-established here rather than inherited from issuance.
	if err := checkOwned(rec.Tags, "Lambda function", componentFunction, name); err != nil {
		return nil, err
	}
	return f.p.functionStatus(rec), nil
}

// WaitForFunction blocks until the function is invocable, fails, or the deadline
// elapses.
func (f *functionRuntime) WaitForFunction(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.FunctionStatus, error) {
	name, err := f.p.resolve(ref, compute.KindFunction)
	if err != nil {
		return nil, err
	}
	var last *compute.FunctionStatus
	err = f.p.await(ctx, opts, func(ctx context.Context) (compute.Status, bool, error) {
		rec, err := f.p.sub.Lambda.GetFunction(ctx, name)
		if err != nil {
			return compute.Status{}, false, f.p.substrateError(err)
		}
		// Same re-check as DescribeFunction, for the same reason: this loop reads
		// the substrate directly rather than through DescribeFunction, so it does
		// not inherit that check for free.
		if err := checkOwned(rec.Tags, "Lambda function", componentFunction, name); err != nil {
			return compute.Status{}, false, err
		}
		last = f.p.functionStatus(rec)
		return last.Status, settled(last.Phase), nil
	})
	if err != nil {
		return last, err
	}
	if last.Phase == compute.PhaseFailed {
		return last, fmt.Errorf("%w: %s", compute.ErrFailed, last.Message)
	}
	return last, nil
}

// DeleteFunction removes a function. Idempotent.
func (f *functionRuntime) DeleteFunction(ctx context.Context, ref compute.Ref) error {
	name, err := f.p.resolve(ref, compute.KindFunction)
	if err != nil {
		return err
	}
	rec, err := f.p.sub.Lambda.GetFunction(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	if err != nil {
		return f.p.substrateError(err)
	}
	// Checked on the way out as well as on the way in. A delete that skipped the
	// ownership check would be a way to remove a resource an Ensure refused to
	// touch, which is a worse hole than the one the check closes.
	if err := checkOwned(rec.Tags, "Lambda function", componentFunction, name); err != nil {
		return err
	}
	err = f.p.sub.Lambda.DeleteFunction(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	// The function's resource policy — every invoke grant an endpoint added —
	// goes with the function. Nothing to detach, which is why this port's
	// obligation to undo its own grants is discharged here rather than
	// enumerated.
	return f.p.substrateError(err)
}

// functionStatus builds what the interface returns, reconstructing the effective
// spec from the substrate.
func (p *Provider) functionStatus(rec *FunctionRecord) *compute.FunctionStatus {
	phase, message := functionPhase(rec)
	spec := compute.FunctionSpec{
		Name:         rec.Tags[tagName],
		Runtime:      rec.Runtime,
		Handler:      rec.Handler,
		Architecture: computeArchitecture(rec.Architecture),
		Resources:    compute.Resources{MemoryMiB: rec.MemoryMiB},
		Timeout:      time.Duration(rec.TimeoutSeconds) * time.Second,
		Env:          envVars(rec.Env),
		Placement:    compute.Placement{Name: rec.Tags[tagPlacement]},
		Labels:       labelsFromTags(rec.Tags),
	}
	if spec.Name == "" {
		spec.Name = rec.Name
	}
	if role := rec.Tags[tagIdentity]; role != "" {
		spec.Identity = p.ref(compute.KindWorkloadIdentity, role)
	}
	// Code is deliberately the zero value: Lambda does not hand a bundle back.
	// See [functionRuntime].
	return &compute.FunctionStatus{
		Status: compute.Status{
			Ref:       p.ref(compute.KindFunction, rec.Name),
			Phase:     phase,
			Message:   message,
			UpdatedAt: time.Now().UTC(),
		},
		Spec:     spec,
		Revision: rec.Revision,
	}
}

// functionPhase maps Lambda's two convergence signals onto one phase.
//
// Both, not one. A function can be Active with an update still in flight, and
// reporting that as ready is what makes the source system's second wait
// necessary (lambda.go:242-245) — it checks both for exactly this reason
// (lambda.go:1000-1013).
func functionPhase(rec *FunctionRecord) (compute.Phase, string) {
	switch {
	case rec.State == FunctionStateFailed:
		return compute.PhaseFailed, rec.StateReason
	case rec.LastUpdateStatus == UpdateStatusFailed:
		return compute.PhaseFailed, rec.StateReason
	case rec.State == FunctionStateActive &&
		(rec.LastUpdateStatus == UpdateStatusSuccessful || rec.LastUpdateStatus == ""):
		return compute.PhaseReady, ""
	default:
		return compute.PhasePending, rec.StateReason
	}
}

// envVars renders a substrate environment as the interface's ordered form, keys
// sorted so that a read-back is stable.
func envVars(env map[string]string) []compute.EnvVar {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]compute.EnvVar, 0, len(keys))
	for _, k := range keys {
		out = append(out, compute.EnvVar{Name: k, Value: env[k]})
	}
	return out
}
