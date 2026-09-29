// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
)

// relationalProvisioner implements [compute.RelationalProvisioner] with Aurora
// Serverless v2.
//
// It is the source system's database.go:151-403 — a security group, a DB subnet
// group, a cluster, and a writer instance inside it — behind one method, which
// is what [compute.RelationalProvisioner] asks for: "Aurora requires creating a
// cluster and then separately creating an instance inside it; that is an Aurora
// fact, and a caller asking for a Postgres endpoint should not learn it."
//
// Five things are different, and each of them is a behaviour change rather than
// a translation.
//
// **The password is never rotated, and the substrate cannot rotate it.**
// [compute.RelationalSpec.AdminPassword] forbids it, because the caller's stored
// copy would silently become wrong and the next deploy's role provisioning would
// fail with an authentication error nothing traces back to the change. The source
// system gets this right by checking for an existing cluster before generating a
// password at all (container.go:288-300). Here the check is in EnsureRelational
// *and* [RDSAPI] has no method that could change a master password, so the rule
// holds by construction rather than by remembering to look first.
//
// **Ingress is declarative and reconciled.** The source authorises ingress once
// and never revokes it, so a rule it wrote outlives the spec that asked for it.
// See [Provider.reconcileIngress].
//
// **A missing control-plane security group is a refusal.** The source has no
// equivalent — it skips an empty entry silently (database.go:207-210) — and the
// alternative to refusing is a connection that times out with no diagnosis, or a
// port opened to everything.
//
// **Storage encryption is not optional.** The source sets StorageEncrypted
// (database.go:311) and so does this, and there is no configuration to turn it
// off: an unencrypted managed database is not a trade-off this provider offers.
//
// **The capacity range is honoured or refused, never rounded.** See
// [RelationalConfig.acuRange].
type relationalProvisioner struct{ p *Provider }

var _ compute.RelationalProvisioner = (*relationalProvisioner)(nil)

// EnsureRelational creates or converges a relational endpoint.
//
// # Ordering
//
// The order below is load-bearing and it is the source system's, for its
// reasons. The security group comes first because the cluster references it; the
// subnet group comes before the cluster for the same reason; the instance comes
// after the cluster because RDS refuses an instance in a cluster that does not
// exist; and the control-plane ingress is authorised before anything tries to
// connect, which the source learned the hard way (database.go:200-205).
//
// It returns without waiting. An Aurora cluster takes minutes, the source system
// blocks for up to ten of them in two polling loops (database.go:323-346,
// :380-401), and [compute.RelationalProvisioner] is explicit that readiness is a
// separate call with a caller-chosen deadline.
func (r *relationalProvisioner) EnsureRelational(ctx context.Context, spec compute.RelationalSpec) (*compute.RelationalStatus, error) {
	cfg := r.p.cfg.Relational
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	engine, err := cfg.engineName(spec.Engine)
	if err != nil {
		return nil, err
	}
	if err := cfg.checkVersion(spec.Engine, spec.EngineVersion); err != nil {
		return nil, err
	}
	if spec.DatabaseName == "" || spec.AdminUsername == "" {
		return nil, fmt.Errorf("%w: a relational endpoint needs a database name and an admin "+
			"username", compute.ErrInvalidSpec)
	}
	if spec.AdminPassword.IsZero() {
		// The error names the ordering obligation rather than just the missing
		// field, because the obligation is the part a caller gets wrong: store
		// the secret first, so that a provisioning failure leaves a recoverable
		// password rather than an endpoint nobody can log into.
		return nil, fmt.Errorf("%w: a relational endpoint needs an admin password; the caller "+
			"generates it and stores it in a SecretStore *before* provisioning, so that a failure "+
			"here leaves a recoverable account", compute.ErrInvalidSpec)
	}
	minACU, maxACU, err := cfg.acuRange(spec.Capacity)
	if err != nil {
		// Nothing from the spec is interpolated. The capacity range is the
		// reason the call failed and the password is not, and an error is
		// logged, returned to an API caller, and often persisted.
		return nil, err
	}
	pc, err := r.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if err := r.p.checkNetworkPlacement(pc); err != nil {
		return nil, err
	}
	names, err := r.p.relationalNames(spec.Name)
	if err != nil {
		return nil, err
	}
	desiredIngress, err := r.p.ingressRules(ctx, spec.Ingress, pc)
	if err != nil {
		return nil, err
	}

	group, err := r.p.ensureSecurityGroup(ctx, names, pc, spec.Name, spec.Labels)
	if err != nil {
		return nil, err
	}
	if err := r.p.ensureSubnetGroup(ctx, names, pc, spec.Name, spec.Labels); err != nil {
		return nil, err
	}

	tags := databaseTags(names.Cluster, componentRelational, pc.Name, spec.Name, spec.Labels)
	cluster, err := r.p.sub.RDS.DescribeCluster(ctx, names.Cluster)
	switch {
	case err == nil:
		if err := checkOwned(cluster.Tags, "DB cluster", componentRelational, names.Cluster); err != nil {
			return nil, err
		}
		if err := checkClusterImmutables(cluster, spec, engine, names.Cluster); err != nil {
			return nil, err
		}
		// Capacity converges. The password does not, and cannot: see the type
		// comment and [RDSAPI.ModifyClusterCapacity].
		if cluster.MinCapacity != minACU || cluster.MaxCapacity != maxACU {
			if err := r.p.sub.RDS.ModifyClusterCapacity(ctx, names.Cluster, minACU, maxACU); err != nil {
				return nil, r.p.substrateError(err)
			}
		}
		if !equalStrings(cluster.SecurityGroupIDs, []string{group.ID}) {
			if err := r.p.sub.RDS.ModifyClusterSecurityGroups(ctx, names.Cluster, []string{group.ID}); err != nil {
				return nil, r.p.substrateError(err)
			}
		}
		if err := r.p.convergeRDSTags(ctx, cluster.ARN, cluster.Tags, tags); err != nil {
			return nil, err
		}
	case errors.Is(err, ErrNoSuchResource):
		if _, err := r.p.sub.RDS.CreateCluster(ctx, CreateClusterRequest{
			Identifier:     names.Cluster,
			Engine:         engine,
			EngineVersion:  spec.EngineVersion,
			DatabaseName:   spec.DatabaseName,
			MasterUsername: spec.AdminUsername,
			// The one place the caller's material is handed to the substrate.
			// It is converted into the redacting type here rather than being
			// passed as a string, so that nothing between this line and the SDK
			// call holds a plain one.
			MasterPassword:   credentials.NewSecret(compute.RevealSecret(spec.AdminPassword)),
			SubnetGroup:      names.SubnetGroup,
			SecurityGroupIDs: []string{group.ID},
			MinCapacity:      minACU,
			MaxCapacity:      maxACU,
			StorageEncrypted: true,
			Tags:             tags,
		}); err != nil {
			return nil, r.p.substrateError(err)
		}
	default:
		return nil, r.p.substrateError(err)
	}

	if err := r.p.ensureWriterInstance(ctx, names, engine, pc.Name, spec.Name, spec.Labels); err != nil {
		return nil, err
	}
	// Ingress last of the network work and before the caller can connect: the
	// group already exists and is attached, so authorising here rather than
	// before the cluster means a converged rule set is in place by the time
	// EnsureRelational returns.
	if err := r.p.reconcileIngress(ctx, group, desiredIngress); err != nil {
		return nil, err
	}
	return r.DescribeRelational(ctx, r.p.ref(compute.KindRelational, names.Cluster))
}

// checkClusterImmutables refuses a re-Ensure that asks to change something an
// Aurora cluster cannot change after creation.
//
// Convergence is the contract for the fields RDS can modify -- capacity,
// security groups, tags -- and those are converged above. These four are not
// among them, and the arm that converges the others used to return success
// while quietly leaving them at their live values. That is substitution, and
// for the engine version the interface forbids it in as many words:
//
//	compute/database.go: "A provider must reject a spec whose version it cannot
//	supply rather than substitute a different one."
//
// The other three are the same shape with a worse consequence.
// [compute.RelationalSpec.AdminUsername] is half the credential the caller
// stored before provisioning, so a caller that changed it and got a green
// deploy has stored a credential for an account that does not exist, and finds
// out at a connection attempt far from the change that caused it -- exactly the
// failure mode this port's own ordering obligation on AdminPassword exists to
// prevent. DatabaseName is what every connection string names.
//
// So it refuses, the way the sibling key-value port refuses a changed key
// schema: an immutable field that differs means this is a new endpoint rather
// than a reconcile, and only the caller can decide that. [compute.ErrInvalidSpec]
// rather than [compute.ErrFailed] because the spec is what has to change.
//
// Every difference is named, not the first one found. A caller who fixes one
// field, redeploys, and is told about the next has been made to pay for the
// round trip twice.
//
// The version comparison is against the major, because RDS resolves a
// major-only request to a minor of its choosing: a cluster created for "16" is
// running "16.4", and comparing the spec against what RDS selected would report
// a change on every re-Ensure. [Provider.DescribeRelational] recovers the major
// the same way, and [validateRelationalConfig] refuses a configured minor, so
// the spec side is always a major.
func checkClusterImmutables(cluster *ClusterRecord, spec compute.RelationalSpec, engine, identifier string) error {
	var differs []string
	if cluster.Engine != engine {
		differs = append(differs, fmt.Sprintf("engine is %q and the spec asks for %q",
			cluster.Engine, engine))
	}
	if live := majorVersion(cluster.EngineVersion); live != spec.EngineVersion {
		differs = append(differs, fmt.Sprintf("engine version is %q (RDS is running %q) and the "+
			"spec asks for %q", live, cluster.EngineVersion, spec.EngineVersion))
	}
	if cluster.DatabaseName != spec.DatabaseName {
		differs = append(differs, fmt.Sprintf("database name is %q and the spec asks for %q",
			cluster.DatabaseName, spec.DatabaseName))
	}
	if cluster.MasterUsername != spec.AdminUsername {
		differs = append(differs, fmt.Sprintf("admin username is %q and the spec asks for %q",
			cluster.MasterUsername, spec.AdminUsername))
	}
	if len(differs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: DB cluster %q exists and %s; none of these can be changed on an "+
		"existing Aurora cluster, so this is a new endpoint rather than a reconcile. A provider "+
		"that converged the rest and reported success would be substituting the live values for "+
		"the ones asked for -- and an admin username that silently did not change leaves the "+
		"caller holding a credential for an account that does not exist",
		compute.ErrInvalidSpec, identifier, strings.Join(differs, "; "))
}

// checkNetworkPlacement refuses a placement that cannot hold a database.
//
// It is a construction-time property of the configuration checked at use, and it
// is here rather than in [New] because a provider may legitimately have one
// placement that can hold a database and another that cannot — a placement is
// how an operator says where things go, and only some of those places have
// subnets.
func (p *Provider) checkNetworkPlacement(pc PlacementConfig) error {
	if strings.TrimSpace(pc.VPC) == "" {
		return fmt.Errorf("%w: placement %q has no VPC, and a database endpoint needs a security "+
			"group; set PlacementConfig.VPC. The source system recovers this by calling "+
			"DescribeSubnets purely to read the VPC back out (build.go:943-954), which fails as an "+
			"AWS problem rather than as a missing setting", compute.ErrInvalidSpec, pc.Name)
	}
	// Two, because RDS refuses a DB subnet group with fewer and the refusal is
	// better here, where the fix is named, than from RDS.
	if len(pc.Subnets) < 2 {
		return fmt.Errorf("%w: placement %q names %d subnet(s), and RDS requires a DB subnet group "+
			"to span at least two availability zones; set PlacementConfig.Subnets",
			compute.ErrInvalidSpec, pc.Name, len(pc.Subnets))
	}
	for _, s := range pc.Subnets {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%w: placement %q has an empty entry in Subnets",
				compute.ErrInvalidSpec, pc.Name)
		}
	}
	return nil
}

// ensureSecurityGroup creates or adopts the group that fronts the endpoint.
func (p *Provider) ensureSecurityGroup(ctx context.Context, names relationalNames, pc PlacementConfig, logical string, labels map[string]string) (*SecurityGroupRecord, error) {
	desired := databaseTags(names.SecurityGroup, componentRelationalSG, pc.Name, logical, labels)
	group, err := p.sub.EC2.DescribeSecurityGroupByName(ctx, names.SecurityGroup, pc.VPC)
	switch {
	case err == nil:
		// Both tags. A security group and a database are not interchangeable,
		// and the component tag is what says which one this is.
		if err := checkOwned(group.Tags, "security group", componentRelationalSG,
			names.SecurityGroup); err != nil {
			return nil, err
		}
		put, remove := tagDelta(group.Tags, desired)
		if len(remove) > 0 {
			if err := p.sub.EC2.UntagSecurityGroup(ctx, group.ID, remove); err != nil {
				return nil, p.substrateError(err)
			}
		}
		if len(put) > 0 {
			if err := p.sub.EC2.TagSecurityGroup(ctx, group.ID, put); err != nil {
				return nil, p.substrateError(err)
			}
		}
		return group, nil
	case errors.Is(err, ErrNoSuchResource):
		group, err = p.sub.EC2.CreateSecurityGroup(ctx, CreateSecurityGroupRequest{
			Name: names.SecurityGroup,
			VPC:  pc.VPC,
			// EC2 requires a description and stores it. It says what apphub
			// created the group for and names no deployment.
			Description: "apphub-managed database endpoint",
			Tags:        desired,
		})
		if err != nil {
			return nil, p.substrateError(err)
		}
		return group, nil
	default:
		return nil, p.substrateError(err)
	}
}

// ensureSubnetGroup creates or adopts the DB subnet group.
//
// It converges nothing but tags. RDS will not change a subnet group's subnets
// under a live cluster, and a provider that tried would fail in the middle of a
// reconcile; an operator who repoints a placement at different subnets is making
// a migration decision, and this provider says so rather than half-performing it.
func (p *Provider) ensureSubnetGroup(ctx context.Context, names relationalNames, pc PlacementConfig, logical string, labels map[string]string) error {
	desired := databaseTags(names.SubnetGroup, componentRelationalSub, pc.Name, logical, labels)
	existing, err := p.sub.RDS.DescribeSubnetGroup(ctx, names.SubnetGroup)
	switch {
	case err == nil:
		if err := checkOwned(existing.Tags, "DB subnet group", componentRelationalSub,
			names.SubnetGroup); err != nil {
			return err
		}
		if !equalStrings(existing.SubnetIDs, pc.Subnets) {
			return fmt.Errorf("%w: DB subnet group %q spans different subnets from placement %q, "+
				"and RDS will not repoint one under a live cluster; moving an endpoint between "+
				"subnets is a migration rather than a reconcile", compute.ErrInvalidSpec,
				names.SubnetGroup, pc.Name)
		}
		return p.convergeRDSTags(ctx, existing.ARN, existing.Tags, desired)
	case errors.Is(err, ErrNoSuchResource):
		_, err := p.sub.RDS.CreateSubnetGroup(ctx, CreateSubnetGroupRequest{
			Name:        names.SubnetGroup,
			Description: "apphub-managed database subnets",
			SubnetIDs:   pc.Subnets,
			Tags:        desired,
		})
		return p.substrateError(err)
	default:
		return p.substrateError(err)
	}
}

// ensureWriterInstance creates or adopts the writer instance inside the cluster.
func (p *Provider) ensureWriterInstance(ctx context.Context, names relationalNames, engine, placement, logical string, labels map[string]string) error {
	desired := databaseTags(names.Instance, componentRelationalInst, placement, logical, labels)
	existing, err := p.sub.RDS.DescribeInstance(ctx, names.Instance)
	switch {
	case err == nil:
		if err := checkOwned(existing.Tags, "DB instance", componentRelationalInst,
			names.Instance); err != nil {
			return err
		}
		return p.convergeRDSTags(ctx, existing.ARN, existing.Tags, desired)
	case errors.Is(err, ErrNoSuchResource):
		_, err := p.sub.RDS.CreateInstance(ctx, CreateInstanceRequest{
			Identifier:        names.Instance,
			ClusterIdentifier: names.Cluster,
			Class:             p.cfg.Relational.instanceClass(),
			Engine:            engine,
			Tags:              desired,
		})
		return p.substrateError(err)
	default:
		return p.substrateError(err)
	}
}

// convergeRDSTags writes and removes tags so current matches desired.
func (p *Provider) convergeRDSTags(ctx context.Context, arn string, current, desired map[string]string) error {
	put, remove := tagDelta(current, desired)
	if len(remove) > 0 {
		if err := p.sub.RDS.UntagResource(ctx, arn, remove); err != nil {
			return p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := p.sub.RDS.TagResource(ctx, arn, put); err != nil {
			return p.substrateError(err)
		}
	}
	return nil
}

// DescribeRelational reads an endpoint back through the interface.
//
// Everything it reports is recovered from the substrate rather than remembered
// in process, so a read-back says what RDS has and not what the last Ensure
// believed it wrote. The one thing it does not report is the admin password: RDS
// does not hand one back, which is what lets [compute.RelationalStatus] promise
// a read-back carries no material.
func (r *relationalProvisioner) DescribeRelational(ctx context.Context, ref compute.Ref) (*compute.RelationalStatus, error) {
	id, err := r.p.resolve(ref, compute.KindRelational)
	if err != nil {
		return nil, err
	}
	cluster, err := r.p.sub.RDS.DescribeCluster(ctx, id)
	if errors.Is(err, ErrNoSuchResource) {
		return &compute.RelationalStatus{Status: r.p.status(ref, compute.PhaseGone, "")}, nil
	}
	if err != nil {
		return nil, r.p.substrateError(err)
	}

	cfg := r.p.cfg.Relational
	spec := compute.RelationalSpec{
		Name:          logicalFromTags(cluster.Tags, cluster.Identifier),
		Engine:        compute.EnginePostgres,
		DatabaseName:  cluster.DatabaseName,
		AdminUsername: cluster.MasterUsername,
		Capacity: compute.CapacityRange{
			MinUnits: cfg.unitsFromACU(cluster.MinCapacity),
			MaxUnits: cfg.unitsFromACU(cluster.MaxCapacity),
		},
		Placement: r.p.placementFromTags(cluster.Tags),
		Labels:    labelsFromTags(cluster.Tags),
	}
	// The major version the caller asked for, recovered from what RDS selected.
	// RDS resolves a major-only request to a minor, so echoing its EngineVersion
	// back would report a version the caller never named and would make a
	// re-Ensure look like a version change.
	spec.EngineVersion = majorVersion(cluster.EngineVersion)
	// Before the phase, because a describe that could not observe the network
	// policy must not return a status at all.
	spec.Ingress, err = r.p.observedIngress(ctx, cluster.SecurityGroupIDs)
	if err != nil {
		return nil, err
	}

	phase, err := relationalPhase(cluster.Status)
	if err != nil {
		return nil, err
	}
	st := &compute.RelationalStatus{Spec: spec}
	st.Status = r.p.status(ref, phase, "")
	if st.Phase == compute.PhaseReady {
		st.Endpoint = compute.SQLEndpoint{
			Host:         cluster.Endpoint,
			Port:         cluster.Port,
			DatabaseName: cluster.DatabaseName,
			// Aurora presents a server certificate and this provider's callers
			// are expected to verify it. Reporting true is a statement about the
			// substrate; [compute.SQLEndpoint.RequireTLS] is explicit that a
			// caller must not disable TLS because a provider reports false.
			RequireTLS: true,
		}
	}
	if class := r.p.cfg.Relational.instanceClass(); class != DefaultInstanceClass {
		// The honest report of a translation that is not an equivalence, which
		// is the most [compute.CapacityRange] allows. A provisioned instance
		// class does not scale, so the range the caller gave is a ceiling and a
		// floor that nothing moves between.
		st.Message = fmt.Sprintf("instance class %q is not serverless, so the capacity range is "+
			"recorded but nothing scales between its bounds", class)
	}
	return st, nil
}

// majorVersion takes the leading major component of an engine version.
//
// "16.4" becomes "16". It is a translation in one direction only: the interface
// pins major-only versions because "pinning a minor makes provisioning fail the
// day the substrate retires it", and RDS answers with the minor it chose.
func majorVersion(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// relationalClusterPhases is every DBCluster status RDS documents, mapped onto
// the interface's phases.
//
// # Why this is exhaustive and its default is fatal
//
// The first version had a default arm returning [compute.PhasePending], on the
// reasoning that most RDS statuses are transitional and treating an unfamiliar
// one as terminal would abandon a cluster that was about to become available.
// Review was right that this is CONTRACT rule 9 and the reasoning is the trap: a
// gate has two outcomes, and "probably transitional" is a third, tolerant one.
// It converts a *new terminal* status into polling until the caller's deadline
// expires, which deletes the diagnosis and teaches the caller to retry something
// that will never become usable.
//
// So the set is enumerated and anything outside it is an error naming the status.
// The cost is stated plainly: **the day AWS adds a status, this port fails loudly
// on it.** That is the intended trade — a failure naming an unrecognised status
// is one line to fix and impossible to misread, and it is strictly better than a
// wait that never ends.
//
// Sources: the RDS API reference's DBCluster.Status values. Where a status has a
// "-recoverable" variant it is transitional, because the recovery is what it is
// waiting for.
var relationalClusterPhases = map[string]compute.Phase{
	// Serving.
	"available": compute.PhaseReady,
	// Converging. Every one of these is a state the cluster leaves on its own.
	"backing-up":                    compute.PhasePending,
	"backtracking":                  compute.PhasePending,
	"configuring-iam-database-auth": compute.PhasePending,
	"creating":                      compute.PhasePending,
	"failing-over":                  compute.PhasePending,
	"inaccessible-encryption-credentials-recoverable": compute.PhasePending,
	"maintenance":                  compute.PhasePending,
	"migrating":                    compute.PhasePending,
	"modifying":                    compute.PhasePending,
	"promoting":                    compute.PhasePending,
	"renaming":                     compute.PhasePending,
	"resetting-master-credentials": compute.PhasePending,
	"starting":                     compute.PhasePending,
	"storage-config-upgrade":       compute.PhasePending,
	"storage-initialization":       compute.PhasePending,
	"storage-optimization":         compute.PhasePending,
	"update-iam-db-auth":           compute.PhasePending,
	"upgrading":                    compute.PhasePending,
	// Going away.
	"deleting": compute.PhaseDeleting,
	// Terminal without intervention. "stopped" is here rather than under
	// Pending deliberately: a stopped cluster does not start itself, so a Wait
	// on one would never return, and the honest answer is that convergence has
	// stopped and will not resume without a change.
	"cloning-failed":                      compute.PhaseFailed,
	"failed":                              compute.PhaseFailed,
	"inaccessible-encryption-credentials": compute.PhaseFailed,
	"incompatible-parameters":             compute.PhaseFailed,
	"incompatible-restore":                compute.PhaseFailed,
	"migration-failed":                    compute.PhaseFailed,
	"stopped":                             compute.PhaseFailed,
	"stopping":                            compute.PhaseFailed,
}

// relationalPhase maps an RDS cluster status onto the interface's phases, or
// refuses.
func relationalPhase(status string) (compute.Phase, error) {
	if phase, ok := relationalClusterPhases[strings.ToLower(strings.TrimSpace(status))]; ok {
		return phase, nil
	}
	return "", fmt.Errorf("%w: RDS reported cluster status %q, which this provider does not "+
		"recognise. It is refused rather than assumed transitional: a status this provider has "+
		"never seen may be terminal, and treating it as converging turns a diagnosable failure "+
		"into a wait that never ends. If AWS has added a status, add it to "+
		"relationalClusterPhases with the phase it means", compute.ErrFailed, status)
}

// observedIngress recovers the caller's rule set from the security group.
//
// A rule this provider did not write — a CIDR rule, or a port range — is
// reported as a [compute.PeerInternet] rule, which is a shape the caller cannot
// have asked for and the next Ensure will revoke. Reporting it rather than
// dropping it is deliberate: an effective spec that hid an unexplained hole in
// the group would be a read-back that lied about the substrate.
//
// # Why a failed observation fails the describe
//
// The first version swallowed every EC2 error and returned whatever subset it
// could read, on the reasoning that a caller usually wants the endpoint's phase
// and hostname and those do not depend on the group. Review was right that this
// is the wrong direction, and the reason is worth keeping: an empty declarative
// set cannot mean both "observed empty" and "could not observe". A throttled or
// denied EC2 read said *there are no rules* about a group that still had an open
// one — and "no ingress rules" reads as safe, so a check scanning the effective
// spec passes on a population it never obtained.
//
// So the error is classified and returned, and [compute.RelationalStatus] gets
// no partial answer. If partial observation ever becomes an interface
// requirement it needs an explicit unknown state; it cannot be spelled as an
// empty set.
func (p *Provider) observedIngress(ctx context.Context, groups []string) ([]compute.IngressRule, error) {
	out := []compute.IngressRule{}
	for _, id := range groups {
		group, err := p.sub.EC2.DescribeSecurityGroupByID(ctx, id)
		if errors.Is(err, ErrNoSuchResource) {
			// A group the cluster references and EC2 does not have is an
			// observation, not a failure: it contributes no rules, and the next
			// Ensure recreates it. This is the one absence that is knowledge.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading the ingress rules of security group %q: %w",
				id, p.substrateError(err))
		}
		for _, rule := range group.Ingress {
			// [compute.IngressRule] carries one protocol, one port and one peer
			// kind, so most of what EC2 can hold cannot be reported faithfully at
			// this level: an omitted span, an ICMP type, a prefix-list source.
			// Each is reported as the nearest shape the interface has, with what
			// was lost named in the description -- so it is a shape no caller can
			// have asked for, and the next Ensure revokes it, which is the
			// outcome that matters for a rule on a group fronting a database.
			//
			// The lossiness is confined to here on purpose. The substrate record
			// keeps every axis EC2 stated, and revocation is built from that
			// record, so this approximation can never feed a revoke. That
			// separation is the correction: it used to be the substrate
			// representation that was lossy, which made the rule unremovable --
			// or, for a prefix list, invisible.
			r := compute.IngressRule{Port: rule.FromPort.Value, Description: rule.Description.Value}
			var lost []string
			if !rule.FromPort.Set || rule.FromPort != rule.ToPort {
				lost = append(lost, "ports "+portSpan(rule))
			}
			if rule.Protocol != "tcp" && rule.Protocol != "udp" {
				lost = append(lost, "protocol "+rule.Protocol)
			}
			if rule.SourcePrefixList != "" {
				lost = append(lost, "prefix list "+rule.SourcePrefixList)
			}
			if len(lost) > 0 {
				r.Description = fmt.Sprintf("%s [%s: not a rule this provider wrote]",
					rule.Description.Value, strings.Join(lost, ", "))
			}
			if rule.Protocol == "udp" {
				r.Protocol = compute.ProtocolUDP
			} else {
				r.Protocol = compute.ProtocolTCP
			}
			if rule.SourceGroup != "" {
				r.From = compute.Peer{Kind: compute.PeerControlPlane}
			} else {
				r.From = compute.Peer{Kind: compute.PeerInternet}
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// WaitForRelational blocks until the endpoint accepts connections.
func (r *relationalProvisioner) WaitForRelational(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.RelationalStatus, error) {
	var last *compute.RelationalStatus
	st, err := waitFor(ctx, r.p.cfg.pollInterval(), opts, func() (compute.Status, bool, error) {
		s, err := r.DescribeRelational(ctx, ref)
		if err != nil {
			return compute.Status{}, false, err
		}
		last = s
		return s.Status, s.Phase == compute.PhaseReady, nil
	})
	if last == nil {
		return nil, err
	}
	last.Status = st
	return last, err
}

// DeleteRelational removes an endpoint and everything provisioned with it.
//
// # Order, and why teardown deletes more than it created a reference for
//
// The instance goes before the cluster because RDS refuses to delete a cluster
// with a member; the security group goes last because the cluster holds a
// reference to it while it exists. The subnet group goes with them.
//
// All four are reconstructed from the logical name recovered from the reference,
// which is what the determinism contract buys: the source system stores three
// identifiers on the application row to find them again (container.go:263-268),
// and a failed deploy that never wrote that row strands them.
//
// Every step tolerates an absent resource, because teardown has to be
// re-runnable: a failed deploy leaves a partial set and the retry deletes the
// ones that are already gone.
func (r *relationalProvisioner) DeleteRelational(ctx context.Context, ref compute.Ref) error {
	id, err := r.p.resolve(ref, compute.KindRelational)
	if err != nil {
		return err
	}
	// Every name is a function of the cluster identifier the reference carries,
	// so nothing has to be recovered and nothing has to have been persisted.
	// The first version of this tried to recover the *logical* name from a tag
	// and re-derive from that; the mapping from logical to physical is one-way,
	// so it did not round-trip and teardown left the instance, the subnet group
	// and the security group behind. See [Provider.relationalNames].
	names, err := r.p.relationalNamesFor(id)
	if err != nil {
		return err
	}

	if err := r.p.deleteIfPresent(ctx, func() error {
		return r.p.sub.RDS.DeleteInstance(ctx, names.Instance)
	}); err != nil {
		return err
	}
	if err := r.p.deleteIfPresent(ctx, func() error {
		return r.p.sub.RDS.DeleteCluster(ctx, names.Cluster)
	}); err != nil {
		return err
	}
	if err := r.p.deleteIfPresent(ctx, func() error {
		return r.p.sub.RDS.DeleteSubnetGroup(ctx, names.SubnetGroup)
	}); err != nil {
		return err
	}
	// The security group is found by name in whichever placement holds it. It is
	// looked up rather than remembered because its identifier is EC2's and this
	// provider never composes one.
	for _, pc := range r.p.cfg.Placements {
		if strings.TrimSpace(pc.VPC) == "" {
			continue
		}
		group, err := r.p.sub.EC2.DescribeSecurityGroupByName(ctx, names.SecurityGroup, pc.VPC)
		if errors.Is(err, ErrNoSuchResource) {
			continue
		}
		if err != nil {
			return r.p.substrateError(err)
		}
		// Only if it is ours, and ours *as a database network*. A group under
		// this name that apphub created as something else is not this
		// teardown's to delete.
		if checkOwned(group.Tags, "security group", componentRelationalSG, names.SecurityGroup) != nil {
			continue
		}
		if err := r.p.deleteIfPresent(ctx, func() error {
			return r.p.sub.EC2.DeleteSecurityGroup(ctx, group.ID)
		}); err != nil {
			return err
		}
	}
	return nil
}

// deleteIfPresent runs a delete and treats an absent resource as success.
//
// It exists so that "teardown is re-runnable" is one line at each call site
// rather than a four-line pattern repeated seven times, which is how one of them
// ends up subtly different.
func (p *Provider) deleteIfPresent(_ context.Context, del func() error) error {
	err := del()
	if err == nil || errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	return p.substrateError(err)
}

// equalStrings compares two string slices as ordered sequences.
//
// slices.Equal rather than a hand-written loop: the loop is where an index
// mistake lives, and the static analyser is right that it cannot prove the
// second index is in range from the length comparison above it.
func equalStrings(a, b []string) bool { return slices.Equal(a, b) }
