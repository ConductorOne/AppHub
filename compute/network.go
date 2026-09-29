// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

// Placement names where a provider should run a workload or put a resource.
//
// This is the load-bearing decision of the whole network model, so it is worth
// stating plainly what it refuses to do. In the source system, placement is a
// list of AWS subnet IDs read from admin configuration and threaded by hand
// through every call: into CreateService's AwsvpcConfiguration and into
// CreateDBSubnetGroup, into CreateLoadBalancer, and into DescribeSubnets purely
// to recover the VPC ID that CreateSecurityGroup then needs (source system @
// backend/internal/modules/deploy/container.go, database.go, lambda.go and
// build.go). Thirteen call sites, all passing raw AWS network-object
// identifiers.
//
// The tempting abstraction is Placement{Subnets []string}. That is a fake: it
// keeps every AWS network ID in the interface, gives a Kubernetes provider a
// field it must ignore, and makes the conformance suite unable to say anything
// about it. So Placement carries a name and nothing else. An operator
// configures what the name means when they construct the provider — subnets,
// security groups, cluster ARN and public-IP policy for AWS; namespace, node
// selector and network-policy defaults for Kubernetes — and the network
// identifiers never enter this package at all.
//
// The consequence, stated honestly: apphub can no longer make per-deploy
// network decisions. It could not really make them before either — the source
// system has exactly one ECSClusterConfig row and every application lands in it
// — but if that changes, the answer is more named placements, not network
// fields here.
//
// # Region
//
// There is no region field, and its absence is deliberate rather than an
// oversight. The source system carries a per-application region string
// (database/application.go:798-810) and uses it to build the AWS config for
// that deploy. A region is a location, so it is a placement: an operator who
// wants applications in two regions configures two placements, and an
// application selects one by name.
//
// The trade is real and belongs to whoever ports the admin surface. Today an
// operator types a region; under this model they choose from the placements
// that exist. That is stricter — an unusable region string currently degrades
// to a logged warning and a silent fallback, which leaves resources stranded in
// a region nothing addresses — but it is a change in behaviour and in UX, not
// a like-for-like port.
type Placement struct {
	// Name identifies an operator-configured placement. The empty name means
	// the provider's default placement; a provider with no default must return
	// [ErrInvalidSpec] rather than guess.
	Name string
}

// Protocol is a transport protocol for a reachability rule.
type Protocol string

// The transport protocols the interface admits. The source system only ever
// authorises TCP; UDP is here because refusing it would be an arbitrary
// restriction, not because anything needs it yet.
const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// PeerKind classifies who is being allowed to reach a workload.
//
// Rules are expressed between *roles in the system*, not between network
// objects. That is the substantive difference from a security group: "the
// platform's ingress proxy may reach this app on its container port" is a
// sentence a Kubernetes NetworkPolicy, an AWS security group, and an on-prem
// firewall can each implement, whereas "security group sg-0123 may reach
// security group sg-4567" is only a sentence AWS can hear.
type PeerKind string

const (
	// PeerInternet is unrestricted inbound from outside the platform. Used for
	// a public load balancer (lambda.go:580-586, which opens each ALB port to
	// 0.0.0.0/0 and ::/0) and, when no ingress proxy is configured, for an
	// application's own container port (build.go:836-848).
	//
	// It is the one peer whose meaning is *wider* on some substrates than the
	// security group it replaces. A Kubernetes NetworkPolicy expresses it as an
	// ipBlock of 0.0.0.0/0, which admits every pod in the cluster as well as the
	// internet, because a NetworkPolicy has no way to say "not from inside". A
	// caller reaching for this because it wants a public port gets more than it
	// asked for there. Named rather than fixed: constraining it would mean
	// inventing a peer that most substrates cannot express either.
	PeerInternet PeerKind = "internet"

	// PeerPlatformIngress is whatever reverse proxy fronts deployed
	// applications. On AWS that is the Traefik security group named by the
	// operator's configuration — the source system reads it from
	// TRAEFIK_SECURITY_GROUP_ID (build.go:822-834); on Kubernetes it is the
	// ingress controller's pods. A provider that has no ingress proxy
	// configured must reject a rule naming this peer rather than silently
	// widening it to [PeerInternet], which is what the source system does, and
	// must not advertise [CapPlatformIngress] so a caller can find that out
	// before it deploys.
	PeerPlatformIngress PeerKind = "platform-ingress"

	// PeerControlPlane is apphub itself. Needed because database provisioning
	// runs from the control plane, not from the application: apphub connects
	// to a freshly created Postgres endpoint to CREATE EXTENSION and CREATE
	// ROLE (source system @
	// backend/internal/modules/deploy/database_extensions.go and
	// postgres_roles.go), which the source system enables by authorising every
	// control-plane security group onto port 5432 (source system @
	// backend/internal/modules/deploy/database.go).
	PeerControlPlane PeerKind = "control-plane"

	// PeerWorkload is another workload deployed by this platform, identified by
	// its [Ref]. Replaces the security-group-to-security-group ingress pattern
	// used to let an application reach its own database (source system @
	// backend/internal/modules/deploy/database.go).
	PeerWorkload PeerKind = "workload"
)

// Peer is the source side of an [IngressRule].
type Peer struct {
	// Kind is which role may connect.
	Kind PeerKind
	// Workload identifies the peer when Kind is [PeerWorkload]. Ignored
	// otherwise; set on any other kind, it is [ErrInvalidSpec].
	Workload Ref
}

// IngressRule allows inbound traffic to the resource it is attached to.
//
// Rules are declarative and complete: the set attached to a spec is the desired
// state, and a provider reconciles to exactly that set on every Ensure. This
// removes a real bug class. In the source system ingress is authorised once, at
// security-group creation (build.go:785-855), so changing an application's
// container port later leaves the old port open and the new one closed — a
// defect patched by a separate ReconcileContainerPortIngress function
// (build.go:888-940) that the caller has to remember to invoke. Under a
// declarative contract there is nothing to remember.
type IngressRule struct {
	// From is who may connect.
	From Peer
	// Port is the destination port on the workload.
	Port int
	// Protocol defaults to [ProtocolTCP] when empty.
	Protocol Protocol
	// Description is operator-facing text. It must not contain identifiers a
	// provider would have to parse.
	Description string
}

// Egress is deliberately not modelled, and that omission carries an obligation
// rather than nothing.
//
//	A provider MUST NOT restrict a workload's outbound traffic, because the
//	interface gives a caller no way to declare what a workload needs to reach.
//	A platform with a default-deny egress posture must permit apphub's
//	workloads out of band.
//
// The absence is harmless on AWS, where a security group allows all egress by
// default, which is why the source system never expresses one. It is not
// harmless everywhere: a Kubernetes NetworkPolicy that listed egress at all
// would become deny-all outbound, cutting an application off from the database
// it was just granted. So a provider writes an ingress-only policy and leaves
// outbound to whatever the cluster does.
//
// The consequence a reader should not have to discover for themselves: on a
// default-deny-egress cluster — a common hardening baseline — the inputs in this
// package are NOT sufficient to make an application reach its own database, even
// though the database's [IngressRule] set correctly names that application as a
// peer. Reachability is two-sided and this interface models one side. An
// EgressRule mirroring [IngressRule] is the obvious v2 shape, and it is not in
// v1 because no call site in the source system needs one, so there is nothing to
// validate a design against.

// Route expresses "make this workload reachable at this hostname" to whatever
// ingress fronts applications on this platform.
//
// On AWS this becomes the Traefik docker labels the source system writes into
// the task definition (source system @
// backend/internal/modules/deploy/container.go); on Kubernetes it becomes an
// Ingress or HTTPRoute. What travels is the intent — host, paths, target port,
// whether the platform's authentication sits in front — not the label grammar.
//
// Hostnames are supplied whole by the caller. The source system composes them
// from a hardcoded internal domain suffix (source system @
// backend/internal/modules/deploy/container.go), which is
// a site-specific identifier that must not exist in this repository; the
// platform's public domain is operator configuration, and building the FQDN is
// the caller's job.
type Route struct {
	// Host is the fully-qualified hostname to route from.
	Host string
	// PathPrefixes optionally narrows the route to these prefixes. Empty means
	// the whole host.
	PathPrefixes []string
	// TargetPort is the workload port to forward to.
	TargetPort int
	// TLS is the certificate the platform's ingress serves for Host.
	//
	// Nil means the route is served as plaintext, which a provider MUST refuse
	// unless AllowPlaintext is set. A public application hostname served over
	// HTTP is a fail-open default, and it is the same defect as the source
	// system's certificate-less HTTPS listener (lambda.go:696-708) one layer
	// down: this interface made a certificate mandatory there
	// ([ListenerSpec.TLS]) and would be inconsistent to leave the hostname every
	// deployed application actually gets unencrypted by omission.
	//
	// A provider must not invent a certificate to fill this in — the same rule
	// as [TLSConfig], for the same reason.
	TLS *TLSConfig

	// AllowPlaintext permits a route with no TLS, for a platform that terminates
	// TLS somewhere this interface cannot see: an edge proxy, a service mesh, a
	// load balancer in front of the ingress. It is an explicit field rather than
	// an inference so that serving an application over HTTP is a decision
	// somebody wrote down.
	AllowPlaintext bool

	// Internal serves the route only on the platform's internal ingress,
	// reachable from inside the network and never from the internet. A
	// provider without an internal ingress must refuse the route rather than
	// publish it on the public one.
	Internal bool

	// RequireAuth asks the platform's ingress to authenticate requests before
	// forwarding. The interface conveys the intent only: what "authenticated"
	// means, and the middleware chain that implements it, belong to the
	// platform's ingress layer, not to a compute provider. A provider whose
	// ingress cannot enforce it must fail the spec rather than route
	// unauthenticated traffic to a workload that asked not to receive it, and
	// must not advertise [CapIngressAuth].
	RequireAuth bool
	// PublicPaths are paths under this route that bypass RequireAuth. Ignored
	// when RequireAuth is false.
	PublicPaths []string

	// MCPAuthApplicationID protects the route's /mcp endpoint with the
	// platform's OAuth server, publishes protected-resource discovery on Host,
	// and identifies the application whose current configuration authorizes
	// that route. Empty leaves /mcp governed by the base route.
	//
	// A provider unable to install both the auth and discovery routes must fail
	// the spec and must not advertise [CapMCPAuth].
	MCPAuthApplicationID string
}
