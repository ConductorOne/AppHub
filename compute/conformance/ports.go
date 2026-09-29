// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/conductorone/apphub/compute"
)

// Variant selects which of two specs a check applies.
//
// Two is enough for every invariant here: one to create with, and one that
// differs in a declarative field so that convergence can be distinguished from
// accumulation. The removed element is what an additive implementation leaves
// behind.
type Variant int

// The spec variants.
const (
	// Base is the initial spec.
	Base Variant = iota
	// Changed is the same resource with a declarative element removed or
	// altered.
	Changed
)

// secretSentinel is the material the suite stores in every secret it creates.
// It is distinctive so that finding it anywhere else is unambiguous.
const secretSentinel = "conformance-sentinel-never-log-8f3a1c2b"

// Port describes one testable port.
type Port struct {
	// Name identifies the port in check names and failure messages.
	Name string
	// Kind is the reference kind the port issues.
	Kind compute.Kind
	// Class is the port class, which decides which invariants apply.
	Class Class
	// Capability is what the port requires, empty when every provider has it.
	Capability compute.Capability
	// HasGranter reports whether the port implements [compute.Granter].
	//
	// It mirrors [compute.WorkloadGrantPorts], and TestPortListMatchesTheAudit
	// pins the two together: the rule "Granter goes on a port only when the
	// substrate authorises by workload identity" is enforced in the interface's
	// own tests, and this is where the suite agrees with it. Driving grant
	// invariants at a port without one — the relational port, or the image
	// registry — would be a suite bug rather than a provider bug.
	HasGranter bool

	// Iface is the [compute] interface this port is a view of.
	//
	// It is what lets a check enumerate the port's methods and ask what its
	// arguments can carry instead of restating either by hand. Both of the
	// hand-maintained restatements it replaced had drifted; see drive.go.
	Iface reflect.Type

	// Methods pairs each uniform operation with the name of the Iface method it
	// calls, so a failure names the method a provider author has to look at and
	// TestEveryPortMethodIsDrivenOrNamed can compare the two sets. An operation
	// missing from here, or an entry here for an operation the port does not
	// have, is a suite bug and is reported as one.
	Methods map[portOp]string

	// PlantsSecretMaterial reports whether the spec this port's Ensure applies
	// carries the suite's sentinel — either as material or as a binding to it.
	//
	// It is checked against Iface: a port that claims to plant material its
	// interface cannot carry, or whose interface carries material while the port
	// neither plants it nor appears in unplantedMaterialPorts, fails the
	// coverage test.
	PlantsSecretMaterial bool

	// ops builds the port's operations against p, or returns the provider's
	// refusal.
	ops func(tb TB, e *Env, p compute.Provider) (*portOps, error)
}

// Available reports whether the provider advertises this port.
func (pt Port) Available(caps compute.CapabilitySet) bool {
	return pt.Capability == "" || caps.Has(pt.Capability)
}

// portOps is the uniform shape a check drives a port through.
type portOps struct {
	// Ensure applies a variant of the port's spec under a logical name. Status
	// is nil for a synchronous port.
	Ensure func(name string, v Variant) (compute.Ref, *compute.Status, error)

	// Describe reads current state back. For a synchronous port it returns a
	// Status carrying only the reference, and [compute.ErrNotFound] once the
	// resource is deleted. Nil when the interface offers no read-back at all,
	// in which case NoReadBack says so.
	Describe func(ref compute.Ref) (*compute.Status, error)

	// NoReadBack explains why Describe is nil. It is reported as a contract
	// observation, because a port with no read-back cannot be reconciled or
	// verified by anything above it.
	NoReadBack string

	// Wait is the port's Wait call, nil for a synchronous port.
	Wait func(ref compute.Ref, opts compute.WaitOptions) (*compute.Status, error)

	// Delete removes the resource.
	Delete func(ref compute.Ref) error

	// Empty destroys the resource's data and keeps the resource, nil for a port
	// that has no such call. Only [compute.ObjectStore] does.
	Empty func(ref compute.Ref) error

	// Granter is the port's grant surface, nil when it has none.
	Granter compute.Granter

	// PullGranter is the port's optional [compute.ImagePullGranter], nil when
	// the port is not a registry or the provider cannot authorise a pull by
	// workload identity. It is a second interface on the same port, which is
	// why opOwner exists.
	PullGranter compute.ImagePullGranter

	// Scale is the port's imperative scale call, nil for a port that has none.
	// Only [compute.ContainerRuntime] does.
	Scale func(ref compute.Ref, replicas int) error

	// Observed reports the declarative state the interface exposes for this
	// resource. Nil when it exposes none.
	Observed func(ref compute.Ref) (map[string]string, error)

	// ChangedKeys are the Observed keys that must differ between [Base] and
	// [Changed]. Empty means the interface exposes nothing that reflects the
	// change, which the suite records rather than hides.
	ChangedKeys []string

	// RemovedFromRendered is a substring that a rendered artefact must contain
	// after [Base] and must not contain after [Changed]. It is the
	// provider-specific half of the removal check, kept because a rendered
	// artefact can show things a spec cannot — that a policy object really was
	// rewritten, not just that the provider says so.
	RemovedFromRendered string

	// Spec reads the effective declarative state back through the interface.
	//
	// This is what closed the largest gap the suite reported: before every
	// read-back carried a Spec, the strong half of the convergence invariant
	// could only be checked through Options.Rendered, which a provider is free
	// not to supply — so a provider implementing Ensure as create-or-add could
	// go unnoticed by declining to show its work. Nil only for the secret port,
	// which has no Spec by design.
	Spec func(ref compute.Ref) (any, error)

	// RemovedFromSpec is a substring the marshalled Spec must contain after
	// [Base] and must not contain after [Changed].
	RemovedFromSpec string
}

// ports returns every port the suite knows about, in the order it exercises
// them. The class and grant columns here are the encoding of §7's per-class
// scoping: nothing else in the suite decides which invariants apply where.
func ports() []Port {
	return []Port{
		identityPort(),
		imageRepositoryPort(),
		secretPort(),
		bucketPort(),
		containerServicePort(),
		scheduledJobPort(),
		functionPort(),
		functionEndpointPort(),
		relationalPort(),
		keyValuePort(),
	}
}

// availablePorts returns the ports the provider under test advertises.
func availablePorts(e *Env) []Port {
	var out []Port
	caps := e.Provider.Capabilities()
	for _, p := range ports() {
		if p.Available(caps) {
			out = append(out, p)
		}
	}
	return out
}

func syncStatus(ref compute.Ref) *compute.Status {
	return &compute.Status{Ref: ref}
}

// --- workload identity -----------------------------------------------------

func identityPort() Port {
	return Port{
		Name:  "workload-identity",
		Kind:  compute.KindWorkloadIdentity,
		Class: Sync,
		Iface: reflect.TypeOf((*compute.IdentityService)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:   "EnsureWorkloadIdentity",
			opDescribe: "DescribeWorkloadIdentity",
			opDelete:   "DeleteWorkloadIdentity",
		},
		ops: func(_ TB, e *Env, p compute.Provider) (*portOps, error) {
			svc := p.Identities()
			if svc == nil {
				return nil, errors.New("conformance: Provider.Identities returned nil; every " +
					"provider must be able to give what it runs an identity")
			}
			spec := func(name string, v Variant) compute.WorkloadIdentitySpec {
				s := compute.WorkloadIdentitySpec{
					Name:   name,
					RunsOn: compute.RuntimeContainer,
					Labels: map[string]string{"owner": "conformance", "extra": "present"},
				}
				if v == Changed {
					s.Labels = map[string]string{"owner": "conformance"}
				}
				return s
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					id, err := svc.EnsureWorkloadIdentity(e.ctx, spec(name, v))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return id.Ref, syncStatus(id.Ref), nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					id, err := svc.DescribeWorkloadIdentity(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return syncStatus(id.Ref), nil
				},
				Delete: func(ref compute.Ref) error {
					return svc.DeleteWorkloadIdentity(e.ctx, ref)
				},
				Observed: func(ref compute.Ref) (map[string]string, error) {
					id, err := svc.DescribeWorkloadIdentity(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{
						"attestation.method":  string(id.Attestation.Method),
						"attestation.subject": id.Attestation.Subject,
					}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					id, err := svc.DescribeWorkloadIdentity(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return id.Spec, nil
				},
				RemovedFromSpec:     "extra",
				RemovedFromRendered: "extra=present",
			}, nil
		},
	}
}

// --- image repository ------------------------------------------------------

func imageRepositoryPort() Port {
	return Port{
		Name:       "image-repository",
		Kind:       compute.KindImageRepository,
		Class:      Sync,
		Capability: compute.CapImageRegistry,
		// No Granter since F1. See compute.ImageRegistry.
		HasGranter: false,
		Iface:      reflect.TypeOf((*compute.ImageRegistry)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:     "EnsureRepository",
			opDescribe:   "DescribeRepository",
			opDelete:     "DeleteRepository",
			opGrantPull:  "GrantPull",
			opRevokePull: "RevokePull",
		},
		ops: func(_ TB, e *Env, p compute.Provider) (*portOps, error) {
			reg, err := p.Registry()
			if err != nil {
				return nil, err
			}
			spec := func(name string, v Variant) compute.RepositorySpec {
				s := compute.RepositorySpec{
					Name:       name,
					Retention:  compute.RetentionPolicy{KeepLast: 20},
					ScanOnPush: true,
					Labels:     map[string]string{"owner": "conformance"},
				}
				if v == Changed {
					s.Retention = compute.RetentionPolicy{KeepLast: 5}
				}
				return s
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					repo, err := reg.EnsureRepository(e.ctx, spec(name, v))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					if repo.Prefix == "" {
						return repo.Ref, nil, errors.New("conformance: EnsureRepository returned " +
							"an empty Prefix, so a caller has nothing to push to")
					}
					return repo.Ref, syncStatus(repo.Ref), nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					repo, err := reg.DescribeRepository(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return syncStatus(repo.Ref), nil
				},
				Delete: func(ref compute.Ref) error {
					return reg.DeleteRepository(e.ctx, ref)
				},
				// The optional pull-grant surface, when the provider advertises
				// it. compute.ImagePullGrants is the supported way to reach it
				// and it checks the capability, so a provider that does not
				// advertise it yields nil here rather than a port that refuses.
				PullGranter: pullGranterOf(reg, p),
				// No Granter. Pull access is an obligation on the provider
				// rather than a grant a caller makes, because no registry
				// authorises a workload identity — see compute.ImageRegistry.
				// Driving grant invariants here would test a method the port
				// deliberately does not have.
				Observed: func(ref compute.Ref) (map[string]string, error) {
					repo, err := reg.DescribeRepository(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{
						"retention.keep-last": fmt.Sprint(repo.Spec.Retention.KeepLast),
					}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					repo, err := reg.DescribeRepository(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return repo.Spec, nil
				},
				ChangedKeys:         []string{"retention.keep-last"},
				RemovedFromSpec:     `"KeepLast":20`,
				RemovedFromRendered: "keep-last=20",
			}, nil
		},
	}
}

// --- secret store ----------------------------------------------------------

func secretPort() Port {
	return Port{
		Name:       "secret",
		Kind:       compute.KindSecret,
		Class:      Sync,
		Capability: compute.CapSecretStore,
		Iface:      reflect.TypeOf((*compute.SecretStore)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure: "Put",
			// Describe, not Get. The lifecycle question this op asks is "does
			// it exist" -- and asking it with the operation that returns the
			// material was a suite pulling secret values to establish liveness.
			// Get is still exercised by Observed below, which compares values
			// without printing them.
			opDescribe: "Describe",
			opDelete:   "Delete",
		},
		// SecretSpec.Value is the sentinel itself: this is the one port that is
		// handed material rather than a reference to it.
		PlantsSecretMaterial: true,
		ops: func(_ TB, e *Env, p compute.Provider) (*portOps, error) {
			store, err := p.Secrets()
			if err != nil {
				return nil, err
			}
			value := func(v Variant) string {
				if v == Changed {
					return secretSentinel + "-changed"
				}
				return secretSentinel
			}
			labels := func(v Variant) map[string]string {
				if v == Changed {
					return map[string]string{"owner": "conformance"}
				}
				return map[string]string{"owner": "conformance", "extra": "present"}
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					stored, err := store.Put(e.ctx, compute.SecretSpec{
						Name:   name,
						Scope:  "conformance",
						Value:  compute.NewSecretValue(value(v)),
						Labels: labels(v),
					})
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return stored.Ref, syncStatus(stored.Ref), nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					if _, err := store.Describe(e.ctx, ref); err != nil {
						return nil, err
					}
					return syncStatus(ref), nil
				},
				Delete: func(ref compute.Ref) error { return store.Delete(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					got, err := store.Get(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					// The value is compared, never printed: the suite asserts on
					// a digest-free equality and every failure message below
					// reports only whether it matched.
					return map[string]string{
						"value-matches-base":    fmt.Sprint(compute.RevealSecret(got) == value(Base)),
						"value-matches-changed": fmt.Sprint(compute.RevealSecret(got) == value(Changed)),
					}, nil
				},
				ChangedKeys:         []string{"value-matches-base", "value-matches-changed"},
				RemovedFromRendered: "extra=present",
			}, nil
		},
	}
}

// --- object storage --------------------------------------------------------

func bucketPort() Port {
	return Port{
		Name:       "bucket",
		Kind:       compute.KindBucket,
		Class:      Sync,
		Capability: compute.CapObjectStore,
		HasGranter: true,
		Iface:      reflect.TypeOf((*compute.ObjectStore)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:        "EnsureBucket",
			opDescribe:      "DescribeBucket",
			opDelete:        "DeleteBucket",
			opEmpty:         "EmptyBucket",
			opGrant:         "Grant",
			opRevoke:        "Revoke",
			opDescribeGrant: "DescribeGrant",
		},
		ops: func(_ TB, e *Env, p compute.Provider) (*portOps, error) {
			store, err := p.ObjectStores()
			if err != nil {
				return nil, err
			}
			spec := func(name string, v Variant) compute.BucketSpec {
				s := compute.BucketSpec{
					Name:   name,
					Labels: map[string]string{"owner": "conformance", "extra": "present"},
				}
				if v == Changed {
					s.Labels = map[string]string{"owner": "conformance"}
				}
				return s
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					b, err := store.EnsureBucket(e.ctx, spec(name, v))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					if b.Name == "" || b.URI == "" {
						return b.Ref, nil, errors.New("conformance: EnsureBucket returned an " +
							"empty Name or URI, so the application cannot be told where its storage is")
					}
					return b.Ref, syncStatus(b.Ref), nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					b, err := store.DescribeBucket(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return syncStatus(b.Ref), nil
				},
				Delete: func(ref compute.Ref) error { return store.DeleteBucket(e.ctx, ref) },
				Empty:  func(ref compute.Ref) error { return store.EmptyBucket(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					b, err := store.DescribeBucket(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{"name": b.Name, "class": string(b.Class), "uri": b.URI}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					b, err := store.DescribeBucket(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return b.Spec, nil
				},
				Granter:             store,
				RemovedFromSpec:     "extra",
				RemovedFromRendered: "extra=present",
			}, nil
		},
	}
}

// --- container service -----------------------------------------------------

func containerServicePort() Port {
	return Port{
		Name:       "container-service",
		Kind:       compute.KindService,
		Class:      Async,
		Capability: compute.CapContainerService,
		Iface:      reflect.TypeOf((*compute.ContainerRuntime)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:   "EnsureService",
			opDescribe: "DescribeService",
			opWait:     "WaitForService",
			opScale:    "ScaleService",
			opDelete:   "DeleteService",
		},
		// Env.ServiceSpec binds the secret fixture, so the material is in play
		// whenever the provider also has a secret store to hold it.
		PlantsSecretMaterial: true,
		ops: func(tb TB, e *Env, p compute.Provider) (*portOps, error) {
			rt, err := p.Containers()
			if err != nil {
				return nil, err
			}
			identity := e.ContainerIdentity(tb, p)
			secrets := e.SecretBindings(tb, p)
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					st, err := rt.EnsureService(e.ctx, e.ServiceSpec(name, v, identity, secrets))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return st.Ref, &st.Status, nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					st, err := rt.DescribeService(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return &st.Status, nil
				},
				Wait: func(ref compute.Ref, opts compute.WaitOptions) (*compute.Status, error) {
					st, err := rt.WaitForService(e.ctx, ref, 1, opts)
					if st == nil {
						return nil, err
					}
					return &st.Status, err
				},
				Scale: func(ref compute.Ref, replicas int) error {
					return rt.ScaleService(e.ctx, ref, replicas)
				},
				Delete: func(ref compute.Ref) error { return rt.DeleteService(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					st, err := rt.DescribeService(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{
						"desired-replicas": fmt.Sprint(st.DesiredReplicas),
						"revision":         st.Revision,
					}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					st, err := rt.DescribeService(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return st.Spec, nil
				},
				ChangedKeys:         []string{"desired-replicas", "revision"},
				RemovedFromSpec:     "CONFORMANCE_REMOVED",
				RemovedFromRendered: "CONFORMANCE_REMOVED=present",
			}, nil
		},
	}
}

// ServiceSpec is the service spec the suite drives. It is exported so a provider
// with a substrate-specific precondition can reuse the same shape.
//
// Everything in it is a logical name or a role: a placement name, reachability
// expressed between roles, a hostname the caller composed. No subnet, security
// group, cluster, load balancer, or account identifier appears, and a provider
// that needed one could not be satisfied by this spec — which is the point.
func (e *Env) ServiceSpec(name string, v Variant, identity compute.Ref, secrets []compute.SecretBinding) compute.ServiceSpec {
	spec := compute.ServiceSpec{
		Name:      name,
		Placement: compute.Placement{Name: e.Options.Placement},
		Image:     e.Image(),
		Resources: compute.Resources{CPUMillicores: 512, MemoryMiB: 1024},
		Replicas:  2,
		Ports:     []compute.PortSpec{{Number: 8080, Name: "http"}},
		Env: []compute.EnvVar{
			{Name: "CONFORMANCE_KEPT", Value: "present"},
			{Name: "CONFORMANCE_REMOVED", Value: "present"},
		},
		Secrets:  secrets,
		Identity: identity,
		Ingress: []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8080, Description: "kept"},
			{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 8080, Description: "removed later"},
		},
		// A route carries its own certificate since F4, and a route with neither
		// that nor AllowPlaintext is refused — so the suite's own spec has to
		// say which it means rather than relying on a provider's default. A
		// provider configured with no certificates can only be asked for the
		// explicit plaintext form.
		Routes: []compute.Route{e.route()},
		Labels: map[string]string{"owner": "conformance"},
	}
	if v == Changed {
		// One replica fewer, one environment variable gone, one reachability
		// rule gone. An implementation that adds rather than converges leaves
		// both behind.
		spec.Replicas = 1
		spec.Env = []compute.EnvVar{{Name: "CONFORMANCE_KEPT", Value: "present"}}
		spec.Ingress = spec.Ingress[:1]
	}
	return spec
}

// Image returns an image reference the suite uses for workloads it never runs.
// It resolves nowhere: the reserved .invalid TLD guarantees a provider that tried
// to pull it fails rather than reaching something real.
func (e *Env) Image() compute.ImageRef {
	return compute.ImageRef("registry.invalid/conformance/workload:v1")
}

// --- scheduled job ---------------------------------------------------------

func scheduledJobPort() Port {
	return Port{
		Name: "scheduled-job",
		Kind: compute.KindScheduledJob,
		// Synchronous since F8: a cron entry is live on acceptance, so the port
		// has no Wait and Describe reports ErrNotFound rather than PhaseGone. It
		// was Async with no Wait method, which left three invariants
		// unverifiable and gave a caller no way to block.
		Class:      Sync,
		Capability: compute.CapScheduledJob,
		Iface:      reflect.TypeOf((*compute.ContainerRuntime)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:   "EnsureScheduledJob",
			opDescribe: "DescribeScheduledJob",
			opDelete:   "DeleteScheduledJob",
		},
		ops: func(tb TB, e *Env, p compute.Provider) (*portOps, error) {
			rt, err := p.Containers()
			if err != nil {
				return nil, err
			}
			if !p.Capabilities().Has(compute.CapScheduledJob) {
				return nil, compute.Unsupported(p.Name(), compute.CapScheduledJob)
			}
			identity := e.ContainerIdentity(tb, p)
			spec := func(name string, v Variant) compute.ScheduledJobSpec {
				s := compute.ScheduledJobSpec{
					Name:      name,
					Schedule:  compute.Schedule{Expression: "*/5 * * * *"},
					Placement: compute.Placement{Name: e.Options.Placement},
					Image:     e.Image(),
					Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
					Env: []compute.EnvVar{
						{Name: "CONFORMANCE_KEPT", Value: "present"},
						{Name: "CONFORMANCE_REMOVED", Value: "present"},
					},
					Identity: identity,
					Labels:   map[string]string{"owner": "conformance"},
				}
				if v == Changed {
					s.Schedule = compute.Schedule{Expression: "0 3 * * *", Paused: true}
					s.Env = []compute.EnvVar{{Name: "CONFORMANCE_KEPT", Value: "present"}}
				}
				return s
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					st, err := rt.EnsureScheduledJob(e.ctx, spec(name, v))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return st.Ref, syncStatus(st.Ref), nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					st, err := rt.DescribeScheduledJob(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return syncStatus(st.Ref), nil
				},
				Delete: func(ref compute.Ref) error { return rt.DeleteScheduledJob(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					st, err := rt.DescribeScheduledJob(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{
						"schedule.expression": st.Schedule.Expression,
						"schedule.paused":     fmt.Sprint(st.Schedule.Paused),
					}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					st, err := rt.DescribeScheduledJob(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return st.Spec, nil
				},
				ChangedKeys:         []string{"schedule.expression", "schedule.paused"},
				RemovedFromSpec:     "CONFORMANCE_REMOVED",
				RemovedFromRendered: "CONFORMANCE_REMOVED=present",
			}, nil
		},
	}
}

// --- function --------------------------------------------------------------

func functionPort() Port {
	return Port{
		Name:       "function",
		Kind:       compute.KindFunction,
		Class:      Async,
		Capability: compute.CapFunction,
		Iface:      reflect.TypeOf((*compute.FunctionRuntime)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:   "EnsureFunction",
			opDescribe: "DescribeFunction",
			opWait:     "WaitForFunction",
			opDelete:   "DeleteFunction",
		},
		ops: func(tb TB, e *Env, p compute.Provider) (*portOps, error) {
			rt, err := p.Functions()
			if err != nil {
				return nil, err
			}
			identity := e.FunctionIdentity(tb, p)
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					st, err := rt.EnsureFunction(e.ctx, e.FunctionSpec(name, v, identity))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return st.Ref, &st.Status, nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					st, err := rt.DescribeFunction(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return &st.Status, nil
				},
				Wait: func(ref compute.Ref, opts compute.WaitOptions) (*compute.Status, error) {
					st, err := rt.WaitForFunction(e.ctx, ref, opts)
					if st == nil {
						return nil, err
					}
					return &st.Status, err
				},
				Delete: func(ref compute.Ref) error { return rt.DeleteFunction(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					st, err := rt.DescribeFunction(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{"revision": st.Revision}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					st, err := rt.DescribeFunction(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return st.Spec, nil
				},
				ChangedKeys:         []string{"revision"},
				RemovedFromSpec:     "CONFORMANCE_REMOVED",
				RemovedFromRendered: "CONFORMANCE_REMOVED=present",
			}, nil
		},
	}
}

// FunctionSpec is the function spec the suite drives.
func (e *Env) FunctionSpec(name string, v Variant, identity compute.Ref) compute.FunctionSpec {
	spec := compute.FunctionSpec{
		Name:      name,
		Runtime:   e.Options.FunctionRuntime,
		Handler:   "index.handler",
		Code:      compute.CodeSource{Inline: []byte("conformance bundle")},
		Resources: compute.Resources{MemoryMiB: 256},
		Timeout:   30 * time.Second,
		Env: []compute.EnvVar{
			{Name: "CONFORMANCE_KEPT", Value: "present"},
			{Name: "CONFORMANCE_REMOVED", Value: "present"},
		},
		Identity:  identity,
		Placement: compute.Placement{Name: e.Options.Placement},
		Labels:    map[string]string{"owner": "conformance"},
	}
	if v == Changed {
		spec.Resources = compute.Resources{MemoryMiB: 512}
		spec.Env = []compute.EnvVar{{Name: "CONFORMANCE_KEPT", Value: "present"}}
	}
	return spec
}

// --- function endpoint -----------------------------------------------------

func functionEndpointPort() Port {
	return Port{
		Name:       "function-endpoint",
		Kind:       compute.KindFunctionEndpoint,
		Class:      Async,
		Capability: compute.CapFunctionEndpoint,
		Iface:      reflect.TypeOf((*compute.FunctionRuntime)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:   "EnsureEndpoint",
			opDescribe: "DescribeEndpoint",
			opWait:     "WaitForEndpoint",
			opDelete:   "DeleteEndpoint",
		},
		ops: func(tb TB, e *Env, p compute.Provider) (*portOps, error) {
			rt, err := p.Functions()
			if err != nil {
				return nil, err
			}
			if !p.Capabilities().Has(compute.CapFunctionEndpoint) {
				return nil, compute.Unsupported(p.Name(), compute.CapFunctionEndpoint)
			}
			target := e.EndpointTarget(tb, p)
			spec := func(name string, v Variant) compute.EndpointSpec {
				s := compute.EndpointSpec{
					Name:   name,
					Target: target,
					Listeners: []compute.ListenerSpec{
						{Port: 80, Protocol: compute.ListenerHTTP},
						{Port: 443, Protocol: compute.ListenerHTTPS,
							TLS: &compute.TLSConfig{CertificateRef: e.Options.CertificateRef}},
					},
					Placement: compute.Placement{Name: e.Options.Placement},
					Ingress: []compute.IngressRule{
						{From: compute.Peer{Kind: compute.PeerInternet}, Port: 80},
						{From: compute.Peer{Kind: compute.PeerInternet}, Port: 443},
					},
					Labels: map[string]string{"owner": "conformance"},
				}
				if v == Changed {
					s.Listeners = s.Listeners[1:]
					s.Ingress = s.Ingress[1:]
				}
				return s
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					st, err := rt.EnsureEndpoint(e.ctx, spec(name, v))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return st.Ref, &st.Status, nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					st, err := rt.DescribeEndpoint(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return &st.Status, nil
				},
				Wait: func(ref compute.Ref, opts compute.WaitOptions) (*compute.Status, error) {
					st, err := rt.WaitForEndpoint(e.ctx, ref, opts)
					if st == nil {
						return nil, err
					}
					return &st.Status, err
				},
				Delete: func(ref compute.Ref) error { return rt.DeleteEndpoint(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					st, err := rt.DescribeEndpoint(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{"hostname": st.Hostname}, nil
				},
				// EndpointStatus's hostname is stable across a listener change,
				// so the hostname alone shows nothing. The effective spec does.
				Spec: func(ref compute.Ref) (any, error) {
					st, err := rt.DescribeEndpoint(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return st.Spec, nil
				},
				RemovedFromSpec:     `"Port":80`,
				RemovedFromRendered: "80/plaintext",
			}, nil
		},
	}
}

// --- relational ------------------------------------------------------------

func relationalPort() Port {
	return Port{
		Name:       "relational-database",
		Kind:       compute.KindRelational,
		Class:      Async,
		Capability: compute.CapRelationalDatabase,
		// No Granter, deliberately: relational access control is SQL, above this
		// interface, and no substrate workload identity maps generically onto a
		// SQL principal.
		HasGranter: false,
		Iface:      reflect.TypeOf((*compute.RelationalProvisioner)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:   "EnsureRelational",
			opDescribe: "DescribeRelational",
			opWait:     "WaitForRelational",
			opDelete:   "DeleteRelational",
		},
		// RelationalSpec.AdminPassword is material, not a reference: a provider
		// without a secret store still handles it.
		PlantsSecretMaterial: true,
		ops: func(_ TB, e *Env, p compute.Provider) (*portOps, error) {
			rp, err := p.Relational()
			if err != nil {
				return nil, err
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					st, err := rp.EnsureRelational(e.ctx, e.RelationalSpec(name, v, e.AdminPassword()))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					return st.Ref, &st.Status, nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					st, err := rp.DescribeRelational(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return &st.Status, nil
				},
				Wait: func(ref compute.Ref, opts compute.WaitOptions) (*compute.Status, error) {
					st, err := rp.WaitForRelational(e.ctx, ref, opts)
					if st == nil {
						return nil, err
					}
					return &st.Status, err
				},
				Delete: func(ref compute.Ref) error { return rp.DeleteRelational(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					st, err := rp.DescribeRelational(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{
						"endpoint.host":     st.Endpoint.Host,
						"endpoint.port":     fmt.Sprint(st.Endpoint.Port),
						"endpoint.database": st.Endpoint.DatabaseName,
					}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					st, err := rp.DescribeRelational(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return st.Spec, nil
				},
				RemovedFromSpec:     `"MaxUnits":2`,
				RemovedFromRendered: "capacity=0.5-2",
			}, nil
		},
	}
}

// AdminPassword is the material the suite uses for a relational admin account.
// It is generated per run and never printed.
func (e *Env) AdminPassword() compute.SecretValue {
	return compute.NewSecretValue(secretSentinel + "-admin")
}

// RelationalSpec is the relational spec the suite drives.
func (e *Env) RelationalSpec(name string, v Variant, password compute.SecretValue) compute.RelationalSpec {
	spec := compute.RelationalSpec{
		Name:          name,
		Engine:        e.Options.Engine,
		EngineVersion: e.Options.EngineVersion,
		DatabaseName:  "conformance",
		AdminUsername: "conformance_admin",
		AdminPassword: password,
		Capacity:      compute.CapacityRange{MinUnits: 0.5, MaxUnits: 2},
		Placement:     compute.Placement{Name: e.Options.Placement},
		Ingress: []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 5432,
				Description: "apphub creates roles and extensions"},
		},
		Labels: map[string]string{"owner": "conformance"},
	}
	if v == Changed {
		spec.Capacity = compute.CapacityRange{MinUnits: 0.5, MaxUnits: 4}
	}
	return spec
}

// --- key-value -------------------------------------------------------------

func keyValuePort() Port {
	return Port{
		Name:       "key-value-table",
		Kind:       compute.KindKeyValueTable,
		Class:      Async,
		Capability: compute.CapKeyValueTable,
		HasGranter: true,
		Iface:      reflect.TypeOf((*compute.KeyValueProvisioner)(nil)).Elem(),
		Methods: map[portOp]string{
			opEnsure:        "EnsureKeyValueTable",
			opDescribe:      "DescribeKeyValueTable",
			opWait:          "WaitForKeyValueTable",
			opDelete:        "DeleteKeyValueTable",
			opGrant:         "Grant",
			opRevoke:        "Revoke",
			opDescribeGrant: "DescribeGrant",
		},
		ops: func(_ TB, e *Env, p compute.Provider) (*portOps, error) {
			kv, err := p.KeyValues()
			if err != nil {
				return nil, err
			}
			spec := func(name string, v Variant) compute.KeyValueSpec {
				s := compute.KeyValueSpec{
					Name:         name,
					PartitionKey: "pk",
					SortKey:      "sk",
					Placement:    compute.Placement{Name: e.Options.Placement},
					Labels:       map[string]string{"owner": "conformance", "extra": "present"},
				}
				if v == Changed {
					s.Labels = map[string]string{"owner": "conformance"}
				}
				return s
			}
			return &portOps{
				Ensure: func(name string, v Variant) (compute.Ref, *compute.Status, error) {
					st, err := kv.EnsureKeyValueTable(e.ctx, spec(name, v))
					if err != nil {
						return compute.Ref{}, nil, err
					}
					if st.Name == "" {
						return st.Ref, &st.Status, errors.New("conformance: " +
							"EnsureKeyValueTable returned an empty Name")
					}
					return st.Ref, &st.Status, nil
				},
				Describe: func(ref compute.Ref) (*compute.Status, error) {
					st, err := kv.DescribeKeyValueTable(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return &st.Status, nil
				},
				Wait: func(ref compute.Ref, opts compute.WaitOptions) (*compute.Status, error) {
					st, err := kv.WaitForKeyValueTable(e.ctx, ref, opts)
					if st == nil {
						return nil, err
					}
					return &st.Status, err
				},
				Delete: func(ref compute.Ref) error { return kv.DeleteKeyValueTable(e.ctx, ref) },
				Observed: func(ref compute.Ref) (map[string]string, error) {
					st, err := kv.DescribeKeyValueTable(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return map[string]string{"name": st.Name}, nil
				},
				Spec: func(ref compute.Ref) (any, error) {
					st, err := kv.DescribeKeyValueTable(e.ctx, ref)
					if err != nil {
						return nil, err
					}
					return st.Spec, nil
				},
				Granter:             kv,
				RemovedFromSpec:     "extra",
				RemovedFromRendered: "extra=present",
			}, nil
		},
	}
}

// --- fixtures --------------------------------------------------------------

// ContainerIdentity returns a workload identity for container workloads,
// creating it once per provider name.
func (e *Env) ContainerIdentity(tb TB, p compute.Provider) compute.Ref {
	return e.identity(tb, p, compute.RuntimeContainer)
}

// FunctionIdentity returns a workload identity for function workloads.
func (e *Env) FunctionIdentity(tb TB, p compute.Provider) compute.Ref {
	return e.identity(tb, p, compute.RuntimeFunction)
}

func (e *Env) identity(tb TB, p compute.Provider, runsOn compute.RuntimeKind) compute.Ref {
	tb.Helper()
	key := "identity/" + p.Name() + "/" + string(runsOn)
	if ref, ok := e.fixture(key); ok {
		return ref
	}
	id, err := p.Identities().EnsureWorkloadIdentity(e.ctx, compute.WorkloadIdentitySpec{
		Name:   "cf-identity-" + string(runsOn),
		RunsOn: runsOn,
		Labels: map[string]string{"owner": "conformance"},
	})
	if err != nil {
		tb.Fatalf("conformance: [workload-identity] a workload identity is a prerequisite for "+
			"almost every spec, and EnsureWorkloadIdentity(%s) failed: %v", runsOn, err)
	}
	e.setFixture(key, id.Ref)
	return id.Ref
}

// SecretBindings returns the secret bindings the suite attaches to a workload,
// or nil when the provider has no secret store.
//
// The value behind the binding is [secretSentinel], so every check that inspects
// an error or a rendered artefact is looking for material that is genuinely in
// play rather than for a string nothing was ever asked to protect.
func (e *Env) SecretBindings(tb TB, p compute.Provider) []compute.SecretBinding {
	tb.Helper()
	if !p.Capabilities().Has(compute.CapSecretStore) {
		e.note("provider %q has no secret store, so the invariant that a workload's secrets "+
			"travel by reference could not be exercised through a workload spec", p.Name())
		return nil
	}
	key := "secret/" + p.Name()
	ref, ok := e.fixture(key)
	if !ok {
		store, err := p.Secrets()
		if err != nil {
			tb.Fatalf("conformance: [secret] the provider advertises %q but Secrets() refused: %v",
				compute.CapSecretStore, err)
		}
		stored, err := store.Put(e.ctx, compute.SecretSpec{
			Name:   "cf-workload-secret",
			Scope:  "conformance",
			Value:  compute.NewSecretValue(secretSentinel),
			Labels: map[string]string{"owner": "conformance"},
		})
		if err != nil {
			tb.Fatalf("conformance: [secret] storing the workload secret fixture failed: %v", err)
		}
		ref = stored.Ref
		e.setFixture(key, ref)
	}
	return []compute.SecretBinding{{EnvName: "CONFORMANCE_SECRET", Secret: ref}}
}

// EndpointTarget returns a function for an endpoint to point at.
func (e *Env) EndpointTarget(tb TB, p compute.Provider) compute.Ref {
	tb.Helper()
	key := "endpoint-target/" + p.Name()
	if ref, ok := e.fixture(key); ok {
		return ref
	}
	rt, err := p.Functions()
	if err != nil {
		tb.Fatalf("conformance: [function-endpoint] an endpoint needs a function to target, and "+
			"Functions() refused: %v", err)
	}
	st, err := rt.EnsureFunction(e.ctx, e.FunctionSpec("cf-endpoint-target", Base, e.FunctionIdentity(tb, p)))
	if err != nil {
		tb.Fatalf("conformance: [function-endpoint] creating the target function failed: %v", err)
	}
	e.setFixture(key, st.Ref)
	return st.Ref
}

func (e *Env) fixture(key string) (compute.Ref, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ref, ok := e.fixtures[key]
	return ref, ok
}

func (e *Env) setFixture(key string, ref compute.Ref) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fixtures[key] = ref
}

// route builds the route the suite attaches to a service.
func (e *Env) route() compute.Route {
	r := compute.Route{Host: e.Options.RouteHost, TargetPort: 8080}
	if e.Options.CertificateRef == "" {
		r.AllowPlaintext = true
		return r
	}
	r.TLS = &compute.TLSConfig{CertificateRef: e.Options.CertificateRef}
	return r
}

// pullGranterOf returns the registry's [compute.ImagePullGranter], or nil when
// the provider does not advertise [compute.CapImagePullGrants].
//
// The lookup helper is the supported route and it checks the capability itself,
// so a provider without it produces nil rather than a port that refuses every
// call. The refusal is checked separately, by the capability-negative checks.
func pullGranterOf(reg compute.ImageRegistry, p compute.Provider) compute.ImagePullGranter {
	if !p.Capabilities().Has(compute.CapImagePullGrants) {
		return nil
	}
	g, err := compute.ImagePullGrants(p, reg)
	if err != nil {
		return nil
	}
	return g
}
