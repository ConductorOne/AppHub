// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
)

// Harness is the substrate operations the [compute] interface deliberately does
// not expose, supplied so the conformance suite's hooks have something to call.
//
// Every method is a place the contract talks about a behaviour it gives no
// portable way to observe: putting a resource somewhere without the ownership
// marker, making the substrate throttle, and reading back everything the
// provider wrote. It works only against the in-memory substrate, because each
// of those is either destructive or impossible against a real account — which
// is itself the reason the suite is hermetic.
type Harness struct{ p *Provider }

// Harness returns the substrate hooks for this provider.
func (p *Provider) Harness() *Harness { return &Harness{p: p} }

// errNotMemory is what a hook returns when the provider is wired to a real
// account. It is an error rather than a silent skip: a conformance run that
// quietly stopped checking ownership would be the worst kind of green.
var errNotMemory = errors.New("aws: this hook needs the in-memory substrate")

// CreateUnowned puts a resource where ref points without apphub's ownership
// tag, so that an Ensure has a collision to refuse.
func (h *Harness) CreateUnowned(_ context.Context, ref compute.Ref) error {
	switch ref.Kind {
	case compute.KindImageRepository:
		name, err := h.p.resolve(ref, compute.KindImageRepository)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.ECR.(*MemoryECR)
		if !ok {
			return errNotMemory
		}
		mem.PutUnowned(name)
		return nil
	case compute.KindWorkloadIdentity:
		name, err := h.p.resolve(ref, compute.KindWorkloadIdentity)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.IAM.(*MemoryIAM)
		if !ok {
			return errNotMemory
		}
		mem.PutUnowned(name)
		return nil
	case compute.KindFunction:
		name, err := h.p.resolve(ref, compute.KindFunction)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.Lambda.(*MemoryLambda)
		if !ok {
			return errNotMemory
		}
		mem.PutUnowned(name)
		return nil
	case compute.KindFunctionEndpoint:
		name, err := h.p.resolve(ref, compute.KindFunctionEndpoint)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.ELBv2.(*MemoryELBv2)
		if !ok {
			return errNotMemory
		}
		// The load balancer *and* the target group, because an endpoint is not
		// one object. Planting only the load balancer would let an
		// implementation that checks ownership on the load balancer alone pass a
		// check that is meant to be about the endpoint.
		mem.PutUnowned(name)
		return nil
	case compute.KindSecret:
		name, err := h.p.resolve(ref, compute.KindSecret)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.Parameters.(*MemoryParameters)
		if !ok {
			return errNotMemory
		}
		// A value, because an SSM parameter with no value is not a thing the
		// service stores -- so an unowned parameter that a real collision would
		// hit has one. It is not the material under test and says so.
		mem.PutUnowned(name, compute.NewSecretValue("planted-by-another-tool"))
		return nil
	case compute.KindRelational:
		name, err := h.p.resolve(ref, compute.KindRelational)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.RDS.(*MemoryRDS)
		if !ok {
			return errNotMemory
		}
		mem.PutUnownedCluster(name)
		return nil
	case compute.KindKeyValueTable:
		name, err := h.p.resolve(ref, compute.KindKeyValueTable)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.DynamoDB.(*MemoryDynamoDB)
		if !ok {
			return errNotMemory
		}
		mem.PutUnowned(name)
		return nil

	case compute.KindService:
		name, err := h.p.resolve(ref, compute.KindService)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.ECS.(*MemoryECS)
		if !ok {
			return errNotMemory
		}
		pc, err := h.p.cfg.placement(compute.Placement{})
		if err != nil {
			return err
		}
		mem.PutUnowned(pc.ClusterARN, name)
		return nil
	case compute.KindScheduledJob:
		name, err := h.p.resolve(ref, compute.KindScheduledJob)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.Scheduler.(*MemoryScheduler)
		if !ok {
			return errNotMemory
		}
		mem.PutUnowned(name)
		return nil
	case compute.KindBucket:
		name, err := h.p.resolveFlavoured(ref, flavourBucket)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.S3.(*MemoryS3)
		if !ok {
			return errNotMemory
		}
		mem.PutUnowned(name, h.p.cfg.Region)
		return nil
	default:
		return fmt.Errorf("aws: no substrate resource stands behind a %q", ref.Kind)
	}
}

// Stall makes a resource stop converging, so a Wait against it has something to
// time out on.
//
// Only the asynchronous ports have one, because only they have a phase to be
// stuck in. It is the hook without which two of the suite's Wait invariants skip
// rather than run — a Wait that honours its deadline, and a Wait with no
// deadline being refused.
func (h *Harness) Stall(_ context.Context, ref compute.Ref) error {
	switch ref.Kind {
	case compute.KindFunction:
		name, err := h.p.resolve(ref, compute.KindFunction)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.Lambda.(*MemoryLambda)
		if !ok {
			return errNotMemory
		}
		mem.Stall(name)
		return nil
	case compute.KindFunctionEndpoint:
		name, err := h.p.resolve(ref, compute.KindFunctionEndpoint)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.ELBv2.(*MemoryELBv2)
		if !ok {
			return errNotMemory
		}
		// Both, because readiness is now the conjunction of the load balancer
		// being active and its target being healthy. Stalling only the load
		// balancer would still satisfy the deadline checks today and would stop
		// doing so the moment the readiness rule changed — a hook that holds one
		// of two conditions is a hook that will silently stop stalling.
		mem.Stall(name)
		mem.StallTargets(name)
		return nil
	case compute.KindRelational:
		name, err := h.p.resolve(ref, compute.KindRelational)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.RDS.(*MemoryRDS)
		if !ok {
			return errNotMemory
		}
		mem.Stall(name)
		return nil
	case compute.KindKeyValueTable:
		name, err := h.p.resolve(ref, compute.KindKeyValueTable)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.DynamoDB.(*MemoryDynamoDB)
		if !ok {
			return errNotMemory
		}
		mem.Stall(name)
		return nil
	case compute.KindService:
		// An ECS service, asynchronous for the same reason the other two are: it
		// accepts a task definition immediately and reaches its desired count
		// later. Without this arm the two async-wait invariants report NOT
		// VERIFIED against a port that has exactly the phase they are about.
		//
		// Stalled PER SERVICE, not substrate-wide. The hook has no undo -- a
		// resource that resumed on its own would let a deadline check pass
		// without the deadline being reached, which is why the RDS and DynamoDB
		// arms above are permanent too -- so a stall taken for one ref must not
		// reach another. [MemoryECS.Stall] is the substrate-wide version and is
		// wrong here: measured, it turned wait-reports-progress red three checks
		// after the two it was taken for.
		name, err := h.p.resolve(ref, compute.KindService)
		if err != nil {
			return err
		}
		mem, ok := h.p.sub.ECS.(*MemoryECS)
		if !ok {
			return errNotMemory
		}
		pc, err := h.p.cfg.placement(compute.Placement{})
		if err != nil {
			return err
		}
		mem.StallService(pc.ClusterARN, name)
		return nil
	default:
		// An error rather than a silent success. A stall hook that quietly did
		// nothing would make the deadline checks pass against a resource that
		// converged on its own, which is the worst kind of green.
		return fmt.Errorf("aws: nothing behind a %q can be stalled by this harness", ref.Kind)
	}
}

// Authenticate reports whether a username and password would log in to a
// relational endpoint.
//
// It is what the "a re-Ensure does not rotate the admin password" invariant
// needs, and it is a hook because the interface deliberately gives no portable
// way to ask: apphub reads the master password out of a [compute.SecretStore]
// and presents it to Postgres, and nothing in [compute] models a login.
//
// It returns a boolean rather than an error carrying detail, so that a failed
// authentication cannot become a diagnostic containing the material.
func (h *Harness) Authenticate(_ context.Context, ref compute.Ref, username string, password compute.SecretValue) error {
	name, err := h.p.resolve(ref, compute.KindRelational)
	if err != nil {
		return err
	}
	mem, ok := h.p.sub.RDS.(*MemoryRDS)
	if !ok {
		return errNotMemory
	}
	if !mem.Authenticate(name, username, credentials.NewSecret(compute.RevealSecret(password))) {
		return errAuthentication
	}
	return nil
}

// errAuthentication is a failed login. It carries no detail on purpose: the
// caller only needs to know the credential did not work, and the alternative is
// a message assembled from the credential that did not work.
var errAuthentication = errors.New("aws: the credential did not authenticate")

// errDenied is what a data-plane hook returns when no policy permits the action.
var errDenied = errors.New("aws: no policy on this identity permits the action")

// tableDataPlane evaluates a key-value grant. See [Harness.Read].
func (h *Harness) tableDataPlane(_ context.Context, resource, identity compute.Ref, action string) error {
	table, err := h.p.resolve(resource, compute.KindKeyValueTable)
	if err != nil {
		return err
	}
	role, err := h.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	iam, ok := h.p.sub.IAM.(*MemoryIAM)
	if !ok {
		return errNotMemory
	}
	ddb, ok := h.p.sub.DynamoDB.(*MemoryDynamoDB)
	if !ok {
		return errNotMemory
	}
	arn, ok := ddb.TableARN(table)
	if !ok {
		return fmt.Errorf("%w: table %q", ErrNoSuchResource, table)
	}
	for _, doc := range iam.Policies(role) {
		var parsed policyDocument
		if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
			continue
		}
		for _, st := range parsed.Statement {
			if st.Effect != "Allow" || !slices.Contains(st.Action, action) {
				continue
			}
			resources, ok := st.Resource.([]any)
			if !ok {
				continue
			}
			for _, r := range resources {
				if s, ok := r.(string); ok && s == arn {
					return nil
				}
			}
		}
	}
	return errDenied
}

// InduceTransient makes every substrate call fail in a way a retry would fix,
// across every service this provider talks to, until the returned function is
// called.
//
// Every *call* rather than the next one, since USOSS-60: the conformance retry
// gate drives every method of every port inside one armed window, and a one-shot
// arming was consumed by the first intercepted call — whichever verb it happened
// to be — leaving every method after it scored as unexercised. Measured, that
// was 2 of 6 rather than 6 of 6. See [failNext] for why the one-shot form is
// kept and named separately rather than changed.
//
// Every service, rather than one, because the invariant is about the provider's
// error mapping and the mapping is per-service: an implementation that reached
// [compute.ErrTransient] from ECR and [compute.ErrFailed] from IAM would pass a
// one-service check and still tell a caller to abandon a deploy that would have
// worked.
func (h *Harness) InduceTransient(_ context.Context, err error) (func(), error) {
	// FailUntilStopped, not FailNext: the conformance gate drives every method of
	// every port in one armed window, and the one-shot form is consumed by the
	// first intercepted call -- whichever verb it was -- leaving every method
	// after it scored as unexercised. USOSS-60.
	//
	// # The services are DERIVED, and the reason is that this exact comment
	// # failed to prevent the exact thing it describes
	//
	// This function used to name services one per line, and it drifted at least
	// twice: USOSS-14's three services landed on FailNext post-merge (this port's
	// own B1), and object storage (USOSS-13) added three more with FailNext
	// directly beneath the paragraph telling the author not to. **A comment
	// stating a rule sat immediately above the code breaking it, twice**, which
	// is the strongest argument available that the rule belongs in the code and
	// not in a comment somebody has to remember to extend.
	//
	// So this reflects over Substrate's fields and arms everything that can be
	// armed, with the sticky form, from one place. A new service is armed
	// correctly by being a field with a FailUntilStopped method -- this port's
	// Lambda, ELBv2 and EndpointEC2 among them. [Harness.InjectionArmableServices]
	// derives its population the same way for the same reason, and the two have
	// to agree: an observer that is general over a stimulus that is not measures
	// nothing.
	var stops []func()
	for _, svc := range h.armableInjectors() {
		stops = append(stops, svc.arm(err))
	}
	if len(stops) == 0 {
		return func() {}, errNotMemory
	}
	return func() {
		for _, stop := range stops {
			stop()
		}
	}, nil
}

// InduceTransientKind makes the service behind kind fail every substrate call
// in a way a retry would fix, until the returned function is called.
//
// # Why this exists next to [Harness.InduceTransient]
//
// USOSS-42 gave [conformance.Options.InduceTransient] a kind parameter, the
// same treatment [conformance.Options.InduceDenial] already had (see that
// hook's doc for why). This is the AWS side of that wiring, and it is a
// sibling rather than a replacement: [Harness.InduceTransient] arms every
// substrate at once and several of this package's own unit tests pin that
// behaviour by name (objectstore_test.go's "InduceTransient arms every service
// it reports"), so changing its signature would break tests that are not about
// the conformance suite at all. This method answers the conformance suite's
// narrower question instead: which ONE service backs the port the suite is
// about to drive.
//
// # It does not change what the suite could already verify
//
// USOSS-60 had already made [Harness.InduceTransient] arm every substrate
// field it can reach, which is why this provider measured 38 of 38 methods
// verified across every port before this method existed -- the "five of six AWS
// providers have no secret store" defect USOSS-10 reported was fixed there,
// not here. What this method adds is per-port attribution: a kind whose
// service is not the in-memory implementation now reports THAT PORT as
// undrivable by name, rather than the whole check going fatal because one
// service among many could not be armed.
//
// The switch mirrors [Harness.InduceDenial]'s, and is sticky for every kind
// rather than one-shot for some, because the transient gate -- unlike the
// denial one -- drives every method of a port in one armed window, not just
// the first write.
func (h *Harness) InduceTransientKind(_ context.Context, kind compute.Kind, err error) (func(), error) {
	var sticky interface{ FailUntilStopped(error) func() }
	switch kind {
	case compute.KindImageRepository:
		ecr, ok := h.p.sub.ECR.(*MemoryECR)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = ecr
	case compute.KindWorkloadIdentity:
		iam, ok := h.p.sub.IAM.(*MemoryIAM)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = iam
	case compute.KindSecret:
		params, ok := h.p.sub.Parameters.(*MemoryParameters)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = params
	case compute.KindFunction:
		lambda, ok := h.p.sub.Lambda.(*MemoryLambda)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = lambda
	case compute.KindFunctionEndpoint:
		// ELBv2, the same choice [Harness.InduceDenial] makes and for the same
		// reason: it is the first service EnsureEndpoint reaches after its own
		// validation, so arming it lands the failure inside this port's Ensure
		// rather than in a dependency's.
		elb, ok := h.p.sub.ELBv2.(*MemoryELBv2)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = elb
	case compute.KindRelational:
		rds, ok := h.p.sub.RDS.(*MemoryRDS)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = rds
	case compute.KindKeyValueTable:
		ddb, ok := h.p.sub.DynamoDB.(*MemoryDynamoDB)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = ddb
	case compute.KindService:
		ecs, ok := h.p.sub.ECS.(*MemoryECS)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = ecs
	case compute.KindScheduledJob:
		scheduler, ok := h.p.sub.Scheduler.(*MemoryScheduler)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = scheduler
	case compute.KindBucket:
		s3, ok := h.p.sub.S3.(*MemoryS3)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = s3
	default:
		return func() {}, fmt.Errorf("aws: no substrate service stands behind a %q on this "+
			"provider, so a transient failure cannot be induced for it", kind)
	}
	return sticky.FailUntilStopped(err), nil
}

// InjectionArmableServices names the Substrate fields [Harness.InduceTransient]
// can arm, and the ones it cannot.
//
// Exported for the test that requires the armable set and the observable set to be
// the SAME set. They were not: the observer derived and the arming listed, so two
// services were observed and never stimulated. Two derivations over one population
// have to agree or the pair measures the intersection while reporting the union.
func (h *Harness) InjectionArmableServices() (armable, unarmable []string) {
	for _, svc := range h.armableInjectors() {
		armable = append(armable, svc.field)
	}
	sub := reflect.ValueOf(*h.p.sub)
	typ := sub.Type()
	for i := range sub.NumField() {
		f := sub.Field(i)
		if f.Kind() == reflect.Interface && f.IsNil() {
			continue
		}
		if !slices.Contains(armable, typ.Field(i).Name) {
			unarmable = append(unarmable, typ.Field(i).Name)
		}
	}
	return armable, unarmable
}

// armableInjector is one Substrate field that can have a sticky failure armed.
type armableInjector struct {
	field string
	arm   func(error) func()
}

// armableInjectors walks Substrate once and returns every field that can be armed.
//
// The single source for both [Harness.InduceTransient] and
// [Harness.InjectionArmableServices]. Two functions deriving the same population
// independently is how a helper comes to describe something the code no longer
// does -- which happened: the helper derived while the arming was reverted to a
// literal, and a test comparing the helper against another helper stayed green.
func (h *Harness) armableInjectors() []armableInjector {
	var out []armableInjector
	sub := reflect.ValueOf(*h.p.sub)
	typ := sub.Type()
	for i := range sub.NumField() {
		f := sub.Field(i)
		if f.Kind() == reflect.Interface && f.IsNil() {
			continue
		}
		if svc, ok := f.Interface().(interface{ FailUntilStopped(error) func() }); ok {
			out = append(out, armableInjector{field: typ.Field(i).Name, arm: svc.FailUntilStopped})
		}
	}
	return out
}

// InduceDenial makes the next substrate call behind kind fail the way its
// service spells an authorization failure, so the mapping onto
// [compute.ErrNotPermitted] is exercised rather than assumed.
//
// # Per kind, unlike InduceTransient
//
// [Harness.InduceTransient] arms every service at once because it cannot be told
// which one the suite is about to drive. This hook is given the kind, so it arms
// exactly the service behind that port -- which is what lets the suite report
// how many ports it actually drove instead of asserting over whichever one it
// reached first.
//
// # Why this hook not existing was worse than it looked
//
// Until it did, the denial check reported a clean skip on this provider, and
// this provider mapped a denial to [compute.ErrFailed]. So the repository held a
// sentinel for authorization failures, a check for it, an AWS provider that got
// it wrong, and no run of the check on that provider. An inert gate and a
// correct mapping are indistinguishable from the outside, which is the whole
// reason the check counts ports by name.
//
// A kind with no service behind it gets an error rather than a silent success:
// the suite records that port as unverified by name and drives the others.
//
// # The two function kinds are here because the check passing did not mean they
// were covered
//
// The denial check is provider-level, so it went green on this provider by
// driving a port that *was* armed -- an image repository -- while
// [compute.KindFunction] and [compute.KindFunctionEndpoint] fell to the default
// arm above and were never exercised. A green provider-level check over a subset
// of ports is the same vacuity the paragraph above describes, one level along:
// there, an inert gate looked like a correct mapping; here, another port's
// correct mapping looks like this one's.
//
// These two ports do reach [compute.ErrNotPermitted], and they reach it through
// the same shared [Provider.substrateError] arm -- but "correct by inheritance"
// is a claim, and the point of the hook is that the claim gets driven.
func (h *Harness) InduceDenial(_ context.Context, kind compute.Kind) (func(), error) {
	var mem interface{ FailNext(error) func() }
	// sticky is the same injection for a port whose write path spans more than
	// one substrate service -- see the comment below the switch.
	var sticky interface{ FailUntilStopped(error) func() }
	switch kind {
	case compute.KindImageRepository:
		ecr, ok := h.p.sub.ECR.(*MemoryECR)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = ecr
	case compute.KindWorkloadIdentity:
		iam, ok := h.p.sub.IAM.(*MemoryIAM)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = iam
	case compute.KindSecret:
		// The secret port, which was the last one this hook could not drive: the
		// check reported 8 of 9 and named it, so the ONE port whose subject is
		// authorization was the one whose denial mapping nothing exercised. The
		// mapping was in fact correct -- secret.go reaches ErrNotPermitted and a
		// unit test pins it -- but that is the "correct by inheritance" claim
		// this hook exists to drive rather than accept, and the count is what
		// made the omission visible.
		params, ok := h.p.sub.Parameters.(*MemoryParameters)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = params
	case compute.KindFunction:
		lambda, ok := h.p.sub.Lambda.(*MemoryLambda)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = lambda
	case compute.KindFunctionEndpoint:
		// ELBv2 rather than EC2 or Lambda. An endpoint touches three services and
		// the load balancer is the first one EnsureEndpoint reaches after its
		// validation, so arming it is what makes the denial land inside this
		// port's own Ensure rather than in a dependency's.
		elb, ok := h.p.sub.ELBv2.(*MemoryELBv2)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = elb
	case compute.KindRelational:
		rds, ok := h.p.sub.RDS.(*MemoryRDS)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = rds
	case compute.KindKeyValueTable:
		ddb, ok := h.p.sub.DynamoDB.(*MemoryDynamoDB)
		if !ok {
			return func() {}, errNotMemory
		}
		sticky = ddb

	case compute.KindService:
		// The container port. Without this arm the suite reported that a denial
		// could not be induced here and said exactly why it mattered: an inert
		// hook and a correct mapping look identical from the outside. The
		// mapping was in fact correct, but nothing had established it — which is
		// the same load-bearing-skip shape that made #39 necessary, one level
		// down and for one port.
		ecs, ok := h.p.sub.ECS.(*MemoryECS)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = ecs
	case compute.KindBucket:
		// Added with the object-store port. The denial check drives every port
		// the provider advertises, so a port arriving without a case here would
		// be reported as undrivable and its mapping left unverified -- which is
		// the inert-gate shape this hook exists to close, arriving as an
		// omission instead of an absence.
		s3, ok := h.p.sub.S3.(*MemoryS3)
		if !ok {
			return func() {}, errNotMemory
		}
		mem = s3
	default:
		return func() {}, fmt.Errorf("aws: no substrate service stands behind a %q on this "+
			"provider, so a denial cannot be induced for it", kind)
	}
	// ErrDenied is what every adapter in this package reports for the family of
	// AccessDenied errors, so injecting it exercises the same arm of
	// [Provider.substrateError] that a real 403 reaches. Injecting a raw error
	// instead would exercise the default arm and prove nothing.
	denial := fmt.Errorf("%w: induced by the conformance harness", ErrDenied)

	// One-shot for a port backed by one service; sticky for a port backed by
	// several, and the difference is not stylistic.
	//
	// [failNext.FailNext] arms the next call on the service it is given. For the
	// image-repository and workload-identity ports that is unambiguous: their
	// whole write path is ECR, or IAM, so the next call on that service is the
	// first call the port makes.
	//
	// The relational port is not like that. Its write path spans three services
	// -- a security group in EC2, then a subnet group and a cluster and an
	// instance in RDS, then ingress back in EC2 -- so "the next call on RDS" is
	// several calls into the operation, and which one it is depends on an
	// ordering inside [Provider.EnsureRelational] that this hook has no business
	// knowing. Worse, the failure mode of guessing wrong is quiet in the
	// direction that matters: if the armed call happened to be one the port
	// converges rather than propagates, the one shot would be spent and the
	// Ensure would report success, which the suite can only read as "this
	// provider does not surface denials at all". The message would name the
	// wrong defect.
	//
	// [failNext.FailUntilStopped] removes the guess. Every call on that service
	// is refused until the returned stop runs, so whichever call the port makes
	// first is the one that is denied, and no reordering inside the port can
	// make this hook inert.
	if sticky != nil {
		return sticky.FailUntilStopped(denial), nil
	}
	return mem.FailNext(denial), nil
}

// Read and Write perform a data-plane operation as a workload identity, by
// evaluating the identity's inline policies.
//
// # Why this evaluates the policy rather than consulting a flag
//
// The conformance suite's contract is that a grant is checked by *behaviour*
// rather than by inspecting a policy document, and the reason is exactly the
// defect both grant-carrying ports had to avoid: a grant that writes a
// syntactically valid document naming the wrong actions passes a document
// comparison and fails a read. So this reads back the inline policy the provider
// actually wrote and decides the same way IAM would -- does some statement allow
// this action on this resource -- rather than asking the provider what it thinks
// it granted.
//
// Both evaluators are deliberately small: Allow-only, no conditions, no wildcards
// beyond the "/*" object form, which is the whole of what [bucketAccessPolicy]
// and the key-value grant can emit. An evaluator that handled more than the
// writers can produce would be asserting over inputs that cannot occur.
//
// # Why it dispatches on the resource's kind
//
// This provider vends two Granter ports -- USOSS-14's key-value tables and
// USOSS-13's buckets -- and the suite calls one pair of hooks for both. The
// action, the ARN and the policy name are all per-service, so a single evaluator
// would have to be told which service it was looking at anyway. Dispatching on
// [compute.Ref.Kind] says it once, and a third Granter port arriving without a
// case here is refused rather than silently evaluated against the wrong service:
// an s3:GetObject check against a DynamoDB policy reports no access on a grant
// that is present and correct, which reads as a provider defect.
func (h *Harness) Read(ctx context.Context, resource, identity compute.Ref) error {
	switch resource.Kind {
	case compute.KindBucket:
		return h.bucketDataPlane(ctx, resource, identity, "s3:GetObject")
	case compute.KindKeyValueTable:
		return h.tableDataPlane(ctx, resource, identity, "dynamodb:GetItem")
	default:
		return fmt.Errorf("aws: no data-plane hook for a %q, so a grant on it cannot be checked "+
			"by behaviour; add one with the port", resource.Kind)
	}
}

// Write is the write half of [Harness.Read].
func (h *Harness) Write(ctx context.Context, resource, identity compute.Ref) error {
	switch resource.Kind {
	case compute.KindBucket:
		return h.bucketDataPlane(ctx, resource, identity, "s3:PutObject")
	case compute.KindKeyValueTable:
		return h.tableDataPlane(ctx, resource, identity, "dynamodb:PutItem")
	default:
		return fmt.Errorf("aws: no data-plane hook for a %q, so a grant on it cannot be checked "+
			"by behaviour; add one with the port", resource.Kind)
	}
}

// bucketDataPlane evaluates an object-store grant. See [Harness.Read].
func (h *Harness) bucketDataPlane(ctx context.Context, resource, identity compute.Ref, action string) error {
	flavour, err := bucketFlavour(resource)
	if err != nil {
		return err
	}
	bucket, err := h.p.resolveFlavoured(resource, flavour)
	if err != nil {
		return err
	}
	role, err := h.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	policy, err := grantPolicyName(flavour, bucket)
	if err != nil {
		return err
	}
	doc, err := h.p.sub.IAM.GetRolePolicy(ctx, role, policy)
	if err != nil {
		// No policy is no access, which is what an unauthorised call looks like
		// from the data plane. The hook's own errors must not be routed through
		// the compute taxonomy, so this is a plain error.
		return fmt.Errorf("aws: role %q has no grant on bucket %q: %w", role, bucket, err)
	}
	// The action and the ARN are per-service, for the same reason the policy name
	// is: an s3:GetObject check against a table bucket's policy would report no
	// access on a grant that is present and correct.
	arn := bucketARN(partitionFor(h.p.cfg.Region), bucket)
	switch flavour {
	case flavourTableBucket:
		action = map[string]string{"s3:GetObject": "s3tables:GetTableData", "s3:PutObject": "s3tables:PutTableData"}[action]
		rec, rerr := h.p.sub.S3Tables.GetTableBucket(ctx, bucket)
		if rerr != nil {
			return fmt.Errorf("aws: reading table bucket %q: %w", bucket, rerr)
		}
		arn = rec.ARN
	case flavourVectorBucket:
		action = map[string]string{"s3:GetObject": "s3vectors:GetVectors", "s3:PutObject": "s3vectors:PutVectors"}[action]
		rec, rerr := h.p.sub.S3Vectors.GetVectorBucket(ctx, bucket)
		if rerr != nil {
			return fmt.Errorf("aws: reading vector bucket %q: %w", bucket, rerr)
		}
		arn = rec.ARN
	}
	allowed, err := policyAllows(doc, action, arn)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("aws: role %q is not allowed %s on bucket %q", role, action, bucket)
	}
	return nil
}

// policyAllows reports whether doc permits action on the bucket named by arn.
func policyAllows(doc, action, bucketARN string) (bool, error) {
	var parsed policyDocument
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false, fmt.Errorf("aws: the stored policy is not valid JSON: %w", err)
	}
	objects := bucketARN + "/*"
	for _, st := range parsed.Statement {
		if st.Effect != "Allow" {
			continue
		}
		if !slices.Contains(st.Action, action) {
			continue
		}
		for _, r := range resourceList(st.Resource) {
			// The resource shape has to MATCH THE ACTION, not merely be one of
			// the two the writer emits. Accepting either for both was the
			// original defect: an object action granted against the bare bucket
			// ARN -- which S3 does not honour -- read as allowed here, so
			// mutating the writer to that invalid shape kept the suite green.
			//
			// Bounded to the shapes bucketAccessPolicy can emit, which is the
			// same argument that bounds this evaluator to Allow-only: an
			// evaluator handling more than the writer can produce asserts over
			// inputs that cannot occur.
			if isObjectAction(action) {
				if r == objects {
					return true, nil
				}
				continue
			}
			if r == bucketARN {
				return true, nil
			}
		}
	}
	return false, nil
}

// resourceList normalises the Resource field, which IAM allows as a string or a
// list of strings.
func resourceList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

// AnonymousRead attempts an unauthenticated read of a bucket.
//
// It must fail for a bucket created with PublicAccess false, which is every
// bucket this provider creates. The check is the public-access block rather than
// a real HTTP request: the block is what makes anonymous access impossible, and
// asserting on the mechanism the provider is responsible for is the only thing an
// in-memory substrate can honestly claim.
func (h *Harness) AnonymousRead(ctx context.Context, bucket compute.Ref) error {
	name, err := h.p.resolveFlavoured(bucket, flavourBucket)
	if err != nil {
		return err
	}
	blocked, err := h.p.sub.S3.GetPublicAccessBlock(ctx, name)
	if err != nil {
		return fmt.Errorf("aws: reading the public-access block for %q: %w", name, err)
	}
	if blocked {
		return fmt.Errorf("aws: bucket %q blocks public access, so an anonymous read fails", name)
	}
	return nil
}

// Grants names every bucket grant standing on a workload identity, across all
// three bucket flavours.
//
// It exists because "teardown left nothing behind" is otherwise unobservable: the
// compute interface has no way to enumerate an identity's grants, so a Revoke that
// removed the wrong policy -- or none -- looks identical to one that worked. The
// source system's equivalent enumeration read one page of a paginated API and
// discarded the error (bucket.go:851-859), so a role with more grants than fit in
// a page reported a subset as the whole truth and a teardown said it was done.
// This is the read that makes the fixed version checkable.
func (h *Harness) Grants(ctx context.Context, identity compute.Ref) ([]string, error) {
	role, err := h.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return nil, fmt.Errorf("aws: Grants could not resolve %s: %w", identity, err)
	}
	return listGrants(ctx, h.p.sub.IAM, role)
}

// Rendered dumps everything the provider wrote, across every service.
//
// It carries two of the suite's invariants: that secret material appears in
// nothing the provider renders, and that a declarative element removed from a
// spec is really gone rather than merely reported as gone. The first holds by
// construction here — see [RecordingBuilder] and [RecordingPusher.Dump] — and the
// second is why the repository dump reads the lifecycle policy that is actually
// stored rather than anything the provider remembered.
func (h *Harness) Rendered(context.Context) ([]string, error) {
	// The empty slice is the answer for a substrate holding nothing, and it is a
	// different answer from "this is not the in-memory substrate". Testing
	// `out == nil` conflated the two, so a provider whose substrate was merely
	// empty reported that it could not be inspected.
	//
	// The hook's contract is about **inspectability**, not about content, and
	// both ends of a resource's life are legitimately empty. Two ports found
	// this within ten minutes of each other from opposite directions: here, by
	// writing an invariant that needs the hook *before* anything is created
	// ("a refused call left nothing behind"); and in USOSS-14, by writing one
	// that needs it *after* everything is deleted ("teardown left nothing
	// behind"). Each had exactly one of the two cases, and either alone looks
	// like a corner.
	out := []string{}
	inspectable := false
	if mem, ok := h.p.sub.ECR.(*MemoryECR); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.S3.(*MemoryS3); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.S3Tables.(*MemoryS3Tables); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.S3Vectors.(*MemoryS3Vectors); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.IAM.(*MemoryIAM); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.Builder.(*RecordingBuilder); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.Pusher.(*RecordingPusher); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.Lambda.(*MemoryLambda); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.ELBv2.(*MemoryELBv2); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.EndpointEC2.(*MemoryEndpointEC2); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.Parameters.(*MemoryParameters); ok {
		// Names, tags and tiers -- never a value. MemoryParameters.Dump is the
		// only reader of a stored SecretValue that is not RevealSecret itself,
		// and it does not read one: the suite's "secret material appears in
		// nothing the provider renders" invariant would otherwise be checked
		// against a dump that had been carefully written to pass it.
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	if mem, ok := h.p.sub.RDS.(*MemoryRDS); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}

	// The ECS dump includes each task definition's resolved secrets array, not
	// just the service. That is what makes the suite's
	// secret-material-does-not-appear-in-rendered-artefacts invariant able to
	// see this port at all: the array is where a resolved secret binding lands,
	// so a dump of only the service would scan a surface the material never
	// reaches and report a pass over nothing.
	var scheduledTaskDefs []string
	if mem, ok := h.p.sub.Scheduler.(*MemoryScheduler); ok {
		out = append(out, mem.Dump()...)
		scheduledTaskDefs = mem.CurrentTaskDefinitions()
		inspectable = true
	}
	if mem, ok := h.p.sub.ECS.(*MemoryECS); ok {
		out = append(out, mem.Dump()...)
		if len(scheduledTaskDefs) > 0 {
			out = append(out, mem.DumpTaskDefinitions(scheduledTaskDefs)...)
		}
		inspectable = true
	}
	// The security-group dump includes each group's RULES, not just its name. A
	// dump of group names would let an implementation that never revoked
	// anything pass the suite's "a declarative element removed from a spec is
	// really gone" invariant, because the group is there either way and the
	// rule set is the thing that converges.
	if mem, ok := h.p.sub.EC2.(*MemoryEC2); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}
	// USOSS-10's flag, not `out == nil`. A service that is in-memory and holds
	// nothing dumps zero lines, so an emptiness test reports "not inspectable"
	// for a substrate that was perfectly inspectable and simply empty.
	if mem, ok := h.p.sub.DynamoDB.(*MemoryDynamoDB); ok {
		out = append(out, mem.Dump()...)
		inspectable = true
	}

	// Note the resolution taken here on the rebase: the base branch replaced
	// "out == nil" with an explicit `inspectable` flag, because an empty dump
	// and an uninspectable substrate are different answers and conflating them
	// reports "nothing was rendered" for a provider nothing could be read from.
	// Both of this port's dumps therefore set the flag; using out == nil would
	// have quietly reverted that fix for two services.
	if !inspectable {
		return nil, errNotMemory
	}
	return out, nil
}

// InjectionFired reports whether an induced failure armed on any in-memory
// service has actually been consumed.
//
// It exists for the acceptance criterion USOSS-60 was given: every injected
// failure has to be *observed* to fire. A cell whose injection was never reached
// is not evidence, and counting it as a pass is how a construction reports
// coverage it does not have — "no induced failure surfaced" and "the method
// handles it correctly" are the same silence from outside.
// # The observed set is DERIVED from Substrate, not listed
//
// It used to name ECR, IAM and STS -- the three services that existed when it was
// written. Object storage added S3, S3Tables and S3Vectors to [Substrate] and not
// to this list, so a planted S3 failure fired and this observer returned false:
// **the port was added to the provider and not to its observer, and nothing
// complained**, because a hand-written list of services has no relationship to the
// struct that holds them.
//
// So this reflects over Substrate's fields and asks each one whether it can
// observe an injection. A seventh service is covered by being a field, which is
// the only way it cannot be forgotten. The nil check matters: an unconfigured
// service is a nil interface, and calling through it would panic on exactly the
// providers that legitimately have fewer services.
func (h *Harness) InjectionFired() bool {
	sub := reflect.ValueOf(*h.p.sub)
	for i := range sub.NumField() {
		f := sub.Field(i)
		if f.Kind() == reflect.Interface && f.IsNil() {
			continue
		}
		if svc := asInjector(f.Interface()); svc != nil && svc.injectionFired() {
			return true
		}
	}
	return false
}

// InjectionObservableServices names the Substrate fields this harness can observe
// an injection on, derived the same way [Harness.InjectionFired] derives them.
//
// Exported for the test that asserts the observed set covers every service the
// provider actually has. Without it the derivation is trusted rather than checked,
// and a field of a type that does not implement the observer would drop out of the
// population silently -- which is the defect one level along from the one this
// replaced.
func (h *Harness) InjectionObservableServices() (observable, unobservable []string) {
	sub := reflect.ValueOf(*h.p.sub)
	typ := sub.Type()
	for i := range sub.NumField() {
		f := sub.Field(i)
		if f.Kind() == reflect.Interface && f.IsNil() {
			continue
		}
		if asInjector(f.Interface()) != nil {
			observable = append(observable, typ.Field(i).Name)
		} else {
			unobservable = append(unobservable, typ.Field(i).Name)
		}
	}
	return observable, unobservable
}

// asInjector returns v as a failure injector, or nil when it is not one — a
// substrate wired to something other than the in-memory services.
func asInjector(v any) interface{ injectionFired() bool } {
	f, ok := v.(interface{ injectionFired() bool })
	if !ok {
		return nil
	}
	return f
}

// BuildCredentials reports the material this substrate hands a build.
//
// It exists for conformance's credential-egress check, and the shape of it is
// the whole point: [compute.ImageBuilder] obliges a provider to mint a scoped,
// short-lived credential and never show it to the caller — which is why there is
// no MintPushCredentials on the interface — so the only way to assert the
// material appears in nothing a build emits is for the provider to report it to a
// test.
//
// "Hands a build" is now narrower than it reads, and the check is still the right
// check. Since USOSS-41 this material reaches the push phase and never the phase
// that executes the Dockerfile; what the suite scans is what a whole
// [compute.ImageBuilder.Build] call emitted, which covers both phases, so a
// provider that leaked from either fails. The way to observe the narrower
// property — that the build phase's own environment holds none of it — is
// [RecordingBuilder.LeakEnvironment].
//
// What it returns is exactly what [MemorySTS.AssumeRole] issues, so a leak of any
// of the three is a leak of something a real build genuinely holds. It is not a
// sentinel planted for the check to find.
func (h *Harness) BuildCredentials(context.Context) ([]string, error) {
	if _, ok := h.p.sub.STS.(*MemorySTS); !ok {
		return nil, errNotMemory
	}
	return []string{memoryAccessKeyID, memorySecretAccessKey, memorySessionToken}, nil
}

// The channels [Harness.EmitInto] can put a marker into.
//
// Plain strings rather than the conformance suite's own type, so that this
// package does not depend on the suite that tests it; the caller maps its
// vocabulary onto these. The set is closed and an unknown or unsupported channel
// is a refusal, never a silent success — a hook that accepts a channel it does
// not implement is the false declaration the marker mechanism exists to rule out.
const (
	ChannelBuildLog    = "build-log"
	ChannelBuildError  = "build-error"
	ChannelBuildResult = "build-result"
	ChannelCallError   = "call-error"

	// ChannelStatusMessage is [compute.Status.Message] on a read-back.
	//
	// It is added by USOSS-11, and the comment on [Harness.EmitInto] used to say
	// there deliberately was no such channel because "this provider has no
	// container service, so there is no Status.Message for a check to read".
	// True when written, and this port is what makes it false: a service's
	// message relays the substrate's rollout reason and its latest event.
	//
	// Leaving it refused was not a neutral omission. It is the reason
	// security/secret-bindings-travel-by-reference -- the invariant about THIS
	// port's headline feature -- reported NOT VERIFIED, on the grounds that "a
	// clean scan of it is not evidence". An unmeasured security invariant whose
	// only obstacle is a hook the provider can now answer is the shape this
	// project treats as a defect.
	ChannelStatusMessage = "status-message"
)

// ErrChannelNotHostile reports that this provider cannot emit into a channel.
var ErrChannelNotHostile = errors.New("aws: no emission path for this channel")

// EmitInto makes this provider put marker into the named channel, until it is
// asked again.
//
// It is the hostile mode USOSS-61 requires, and it exists because a benign
// fixture and a correct implementation are indistinguishable: this provider's
// credential-egress check passed while bypassing its redacting writer changed
// nothing, since the in-memory runner wrote only its own arguments. A marker the
// suite chooses, verified by the suite looking, is what makes the scan evidence.
//
// Every channel this provider has an emission path for is implemented, and one
// it does not is refused. See [ChannelStatusMessage] for the one this port
// added and why its absence was not neutral.
func (h *Harness) EmitInto(_ context.Context, channel, marker string) error {
	// An empty marker clears the channel. The suite clears between establishing a
	// channel and scanning it, because a persistent emission poisons the run it is
	// meant to make meaningful: an armed build-error makes every later build fail,
	// which turns the material scan into a skip and hands back a vacuous green by
	// another route.
	switch channel {
	case ChannelBuildLog, ChannelBuildError, ChannelBuildResult:
		runner, ok := h.p.sub.Builder.(*RecordingBuilder)
		if !ok {
			return fmt.Errorf("%w: %q needs the in-memory build runner", ErrChannelNotHostile, channel)
		}
		runner.emitInto(channel, marker)
	case ChannelStatusMessage:
		mem, ok := h.p.sub.ECS.(*MemoryECS)
		if !ok {
			return fmt.Errorf("%w: %q needs the in-memory container substrate",
				ErrChannelNotHostile, channel)
		}
		mem.emitInto(marker)
	case ChannelCallError:
	default:
		return fmt.Errorf("%w: %q", ErrChannelNotHostile, channel)
	}
	h.p.emitMu.Lock()
	defer h.p.emitMu.Unlock()
	if h.p.emissions == nil {
		h.p.emissions = map[string]string{}
	}
	h.p.emissions[channel] = marker
	return nil
}

// CanExecInto reports whether the workload identity behind identity can OPEN an
// interactive session against the workload behind target.
//
// It answers conformance's Options.CanExecInto, which
// security/exec-does-not-widen-the-workload-identity skips without. That skip is
// the shape this project does not accept on a security check for a capability
// the provider advertises: this provider advertises [compute.CapWorkloadExec]
// with the container runtime and ships the ssmmessages grant, so the invariant
// is live and was going unmeasured. It also reports NOT VERIFIED for
// capabilities/workload-exec's positive half for the same reason.
//
// # What "can open" means on AWS, and why the ssmmessages grant is not it
//
// ECS Exec has two halves and they belong to different principals.
// [compute.ServiceSpec.ExecEnabled] expresses the TARGET half: make this
// workload available for sessions, which on AWS means the task role holds
// ssmmessages:{Create,Open}{Control,Data}Channel so the agent inside the task
// can open its side of the channel. The OPENER half — ecs:ExecuteCommand on the
// task, and ssm:StartSession — is the operator's, and the interface is explicit
// that granting it to the workload's own identity is the inversion USOSS-2
// corrected.
//
// So this looks for the OPENER actions and deliberately does not treat the
// channel grants as an answer. A hook that read ssmmessages as "can exec" would
// report true for every exec-enabled workload and turn a correct implementation
// red; one that ignored a real ecs:ExecuteCommand grant would be inert, and an
// inert hook and a correct provider are the same silence — which is the whole
// reason the suite makes this a hook rather than an assumption.
//
// [TestTheExecHookCanSayYes] pins both directions: the real grants answer false,
// and a planted ecs:ExecuteCommand answers true. Without the second half this
// would be a hook that cannot fail.
func (h *Harness) CanExecInto(_ context.Context, identity, target compute.Ref) (bool, error) {
	mem, ok := h.p.sub.IAM.(*MemoryIAM)
	if !ok {
		return false, errNotMemory
	}
	// The target is not read. That is not an omission: the question is whether
	// this IDENTITY holds an opener grant at all, and an identity that holds one
	// can exec into anything the grant's Resource covers. The suite asks it once
	// for the exec-enabled workload and once for a neighbour precisely so that a
	// provider which scoped the grant to one service is still caught -- so the
	// answer has to come from the identity's policies rather than from the pair.
	// Named rather than left to a reader of the signature.
	_ = target
	roleName, err := h.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return false, err
	}
	for _, doc := range mem.RolePolicies(roleName) {
		grants, err := grantsInteractiveSession(doc)
		if err != nil {
			return false, fmt.Errorf("aws: reading the policies on %s: %w", roleName, err)
		}
		if grants {
			return true, nil
		}
	}
	return false, nil
}

// execOpenerActions are the actions that let a principal OPEN an interactive
// session, as opposed to being the target of one.
//
// Enumerated rather than pattern-matched on the "ecs:" prefix, because
// ecs:DescribeTasks is on the same prefix and is not an opener grant, and
// ssmmessages is on the ssm-adjacent one and is the target half.
var execOpenerActions = []string{"ecs:executecommand", "ssm:startsession"}

// grantsInteractiveSession reports whether one policy document allows an opener
// action.
//
// Wildcards count. "ecs:*" and "*" both grant ecs:ExecuteCommand, and a hook
// that only matched the exact spelling would report false for the widest grant
// there is -- which is the direction that matters, since a wildcard is how this
// would actually happen.
func grantsInteractiveSession(document string) (bool, error) {
	// A relaxed shape rather than [PolicyDocument]: IAM accepts a bare string
	// where this package's type declares a slice, and execPolicy is written that
	// way, so unmarshalling into the strict type fails on a document this
	// provider itself produces.
	var doc struct {
		Statement []struct {
			Effect string          `json:"Effect"`
			Action json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return false, err
	}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		actions, err := stringOrList(st.Action)
		if err != nil {
			return false, err
		}
		for _, action := range actions {
			a := strings.ToLower(strings.TrimSpace(action))
			if a == "*" {
				return true, nil
			}
			for _, opener := range execOpenerActions {
				service, _, _ := strings.Cut(opener, ":")
				if a == opener || a == service+":*" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// stringOrList reads an IAM element that is either a string or an array of them.
func stringOrList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, fmt.Errorf("an IAM element is neither a string nor an array of them: %w", err)
	}
	return []string{one}, nil
}

// isObjectAction reports whether an action addresses objects rather than the
// container.
//
// S3 splits its actions across two resource shapes and the split is not a
// convention this package chose: an object action against the bare bucket ARN
// grants nothing, and a bucket action against the "/*" form grants nothing
// either. So the evaluator has to know which side each action is on, or it
// reports access that S3 would refuse.
//
// The two ext services do not split, which is why their policies carry both
// shapes in one statement -- see extAccessPolicy.
func isObjectAction(action string) bool {
	switch action {
	case "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject",
		"s3:AbortMultipartUpload":
		return true
	default:
		// Bucket-level, or a non-S3 service whose actions are not split. Both
		// take the container ARN, which is what the caller then checks.
		return false
	}
}
