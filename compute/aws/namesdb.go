// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// The physical-name rules for the database substrates.
//
// # Why RDS needs its own marker
//
// [digestMarker] is a full stop, and that choice is what makes the two forms of
// a name disjoint sets of strings: the lossless form of a name provably contains
// no character outside [a-z0-9-], so a full stop can only mean "a digest
// follows". An RDS cluster identifier admits letters, digits and single hyphens
// and nothing else — no full stop, and no repeated hyphen either — so that
// alphabet has no spare character at all.
//
// Disjointness is recovered without one. The marker is a hyphen, and a name that
// *already* ends in a hyphen followed by a digest is refused verbatim status and
// digested instead ([hasDigestTail]). The two sets are then still separated by a
// decidable property of the string rather than by an argument about how long the
// digest is:
//
//   - two verbatim names differ because the names differ;
//   - two digested names differ because the digest is over the whole logical
//     name;
//   - a verbatim name and a digested one differ because exactly one of them ends
//     in the marker followed by [digestLength] hex digits.
//
// # The second rule RDS has that nothing else here does
//
// An identifier must **begin with a letter**. A logical name may begin with a
// digit — "9lives" is a perfectly good application name — and the head of a
// digested name is the sanitized logical name, so nothing in [sanitizeWith]
// supplies that property.
//
// It is supplied by requiring a prefix that starts with a letter, checked at
// construction rather than at provisioning time. That makes the property hold
// for *every* name by construction, which is the shape this project prefers to
// a check that notices a violation: the alternative — prepending a letter when
// the head starts with a digit — reintroduces a collision, because an
// application literally named "d9lives" and one named "9lives" would both render
// as "d9lives".
//
// The final name is also matched against [rdsIdentifier] before it is used, so
// the conjunction of the two properties is verified where a failure would
// actually live rather than inferred from each half.
const rdsDigestMarker = "-"

// componentRelational and friends name what a resource is, for an operator
// reading a tag in the console.
//
// One per resource kind, and distinct from every other port's, because
// [checkOwned] requires the component tag to match as well as the ownership tag.
// A single "database" component shared between a cluster and the security group
// that fronts it would make the two interchangeable by name, and a security
// group is not a thing to adopt as a database.
const (
	componentRelational     = "relational-database"
	componentRelationalSG   = "relational-database-network"
	componentRelationalSub  = "relational-database-subnets"
	componentRelationalInst = "relational-database-instance"
	componentKeyValue       = "key-value-table"
)

// rdsIdentifier is the RDS grammar for a cluster or instance identifier: 1 to 63
// characters, beginning with a letter, of lowercase letters, digits and single
// hyphens, not ending in a hyphen.
//
// RDS lowercases an identifier server-side, which is why the pattern is
// lowercase-only rather than case-insensitive: a provider that sent a mixed-case
// identifier would look one resource up under a name RDS stored differently.
var rdsIdentifier = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

// rdsPrefix is the grammar a configured [RelationalConfig.NamePrefix] must
// satisfy for every name derived from it to be a legal RDS identifier: it must
// begin with a letter and may end in a single hyphen, because a head follows it.
var rdsPrefix = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*-?$`)

// dynamoTableName is DynamoDB's grammar: 3 to 255 characters of letters, digits,
// underscores, hyphens and full stops.
var dynamoTableName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,255}$`)

// securityGroupName is EC2's grammar for a group name. It is permissive; the
// one thing it excludes is a name beginning "sg-", which EC2 reserves.
var securityGroupName = regexp.MustCompile(`^[a-zA-Z0-9 ._\-:/()#,@\[\]+=&;{}!$*]{1,255}$`)

// The length ceilings the database substrates impose.
const (
	maxRDSIdentifier   = 63
	maxRDSSubnetGroup  = 255
	maxDynamoTableName = 255
	maxSecurityGroup   = 255
	// maxInlinePolicyName is IAM's ceiling on an inline policy name. It is much
	// tighter than the table-name ceiling above, which is why the grant policy
	// name is derived through the sanitizer rather than concatenated: a 255-byte
	// table name would otherwise render a policy name IAM refuses.
	maxInlinePolicyName = 128
)

// relationalNames is every physical name one relational endpoint needs.
//
// They are derived together, from one logical name, so that a teardown can
// reconstruct all four without anything having been persisted — which is the
// determinism contract, and the reason the source system's need to store
// RDSClusterID, RDSInstanceID and RDSSubnetGroupName on the application row
// (container.go:263-268) goes away.
type relationalNames struct {
	// Cluster is the DB cluster identifier.
	Cluster string
	// Instance is the writer instance identifier.
	Instance string
	// SubnetGroup is the DB subnet group name.
	SubnetGroup string
	// SecurityGroup is the security group name.
	SecurityGroup string
}

// relationalNames renders the four names a relational endpoint needs, all four
// as functions of one injective identifier.
//
// # Why the other three are derived from the cluster identifier and not from the
// logical name
//
// The first version of this derived each name from the logical name with its own
// call to the sanitizer, and it had a defect a test caught: teardown receives a
// [compute.Ref] holding the *cluster identifier*, and there is no way back from a
// physical name to the logical one it was rendered from — the mapping is
// deliberately one-way and lossy. So Delete could not reconstruct the instance,
// the subnet group or the security group, and left all three behind: a stranded
// DB instance nothing addresses, and a security group keeping a hole open.
//
// Deriving them from the cluster identifier fixes it by construction rather than
// by remembering to store something. The cluster identifier is injective in the
// logical name, and appending a constant to it or using it unchanged keeps it
// injective. So all four names are distinct across
// distinct logical names, and all four are reconstructible from the one value a
// [compute.Ref] carries.
//
// The RDS identifier grammar is the narrowest of the four — 63 characters,
// lowercase, leading letter, single hyphens — and it is a subset of the DB subnet
// group and security group grammars, so a name legal as a cluster identifier is
// legal as the other two. That makes the RDS grammar the only one that has to be
// checked.
func (p *Provider) relationalNames(logical string) (relationalNames, error) {
	cfg := p.cfg.Relational
	if cfg == nil {
		return relationalNames{}, p.unsupported(compute.CapRelationalDatabase,
			"no relational database is configured on this provider")
	}
	cluster, err := sanitizeWith(cfg.NamePrefix, logical, maxRDSIdentifier-len(writerSuffix),
		rdsDigestMarker)
	if err != nil {
		return relationalNames{}, fmt.Errorf("%w (check Config.Relational.NamePrefix)", err)
	}
	return p.relationalNamesFor(cluster)
}

// writerSuffix distinguishes the writer instance from its cluster.
//
// "-w" for writer rather than the source system's "-1" (container.go:266),
// because a number implies a series this provider does not create: there is
// exactly one writer instance. The cluster identifier is rendered into
// maxRDSIdentifier minus this suffix's length, so appending it never needs to
// truncate — truncating an already-injective identifier would drop digest
// characters and let two clusters share one instance.
const writerSuffix = "-w"

// securityGroupSuffix keeps the database's security group out of the name set
// of the per-service groups, which share its namespace: one per VPC.
//
// Without it the two collided whenever the container and relational prefixes
// matched, as they do in the shipped Terraform: the service step found the
// database's group under its own name, refused it as not owned, and the deploy
// failed after the database existed. A colon is outside every alphabet a
// service group name is drawn from — an ECS service name admits no colon and
// [sanitize] adds none — so the two sets are disjoint by construction, whatever
// either prefix is.
const securityGroupSuffix = ":db"

// relationalNamesFor derives the set from a cluster identifier, which is what a
// teardown has.
func (p *Provider) relationalNamesFor(cluster string) (relationalNames, error) {
	if !rdsIdentifier.MatchString(cluster) || len(cluster)+len(writerSuffix) > maxRDSIdentifier {
		// The conjunction of injectivity and legality, checked where a failure
		// would live. RDS is what rejects this string, so the RDS grammar is
		// what it is checked against, and the leading-letter rule it carries is
		// the one sanitizeWith cannot supply.
		return relationalNames{}, fmt.Errorf("%w: %q is not a legal RDS cluster identifier with "+
			"room for the %q suffix; an identifier must begin with a letter and hold only "+
			"lowercase letters, digits and single hyphens, in at most %d characters. "+
			"Config.Relational.NamePrefix is what supplies the leading letter",
			compute.ErrInvalidSpec, cluster, writerSuffix, maxRDSIdentifier)
	}
	names := relationalNames{
		Cluster:  cluster,
		Instance: cluster + writerSuffix,
		// The same string. A DB subnet group lives in a different namespace
		// from a cluster, so there is nothing to disambiguate, and reusing the
		// identifier means one injectivity argument covers it.
		SubnetGroup: cluster,
		// A security group does share a namespace, with the per-service groups;
		// see [securityGroupSuffix].
		SecurityGroup: cluster + securityGroupSuffix,
	}
	if !securityGroupName.MatchString(names.SecurityGroup) ||
		strings.HasPrefix(names.SecurityGroup, "sg-") {
		return relationalNames{}, fmt.Errorf("%w: %q is not a legal security group name; check "+
			"Config.Relational.NamePrefix", compute.ErrInvalidSpec, names.SecurityGroup)
	}
	if len(names.SubnetGroup) > maxRDSSubnetGroup || len(names.SecurityGroup) > maxSecurityGroup {
		return relationalNames{}, fmt.Errorf("%w: %q is longer than a DB subnet group or a "+
			"security group name may be", compute.ErrInvalidSpec, cluster)
	}
	return names, nil
}

// tableName renders a logical name as a DynamoDB table name.
func (p *Provider) tableName(logical string) (string, error) {
	cfg := p.cfg.KeyValue
	if cfg == nil {
		return "", p.unsupported(compute.CapKeyValueTable,
			"no key-value table service is configured on this provider")
	}
	name, err := sanitize(cfg.NamePrefix, logical, maxDynamoTableName)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.KeyValue.NamePrefix)", err)
	}
	if !dynamoTableName.MatchString(name) {
		// DynamoDB's floor is three characters, which sanitize does not know
		// about: a one-character logical name with no prefix renders as one
		// character and is refused here rather than by DynamoDB. Padding it
		// would break injectivity against the padded form of another name.
		return "", fmt.Errorf("%w: %q is not a legal DynamoDB table name; a table name is 3 to "+
			"255 characters of letters, digits and _.- — configure Config.KeyValue.NamePrefix if "+
			"short logical names need to be usable", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// tagLogical records the logical name a resource was provisioned for.
//
// [tagName] holds the *physical* name, which is what the resource is called and
// therefore already known from the resource itself. What a read-back needs in
// order to echo the caller's spec is the logical name the caller gave, and the
// mapping from one to the other is deliberately one-way — a digested name cannot
// be inverted. Without this tag, [compute.RelationalStatus.Spec].Name would
// report the physical name, so a caller comparing what it asked for against what
// it got would see a difference on every read.
//
// The workload-identity port (USOSS-10) reports the physical name and has the
// same gap. It is called out in the USOSS-14 report rather than changed here.
const tagLogical = "apphub:logical-name"

// databaseTags are the ownership tags plus the placement and logical-name
// records.
func databaseTags(name, component, placement, logical string, labels map[string]string) map[string]string {
	out := ownershipTags(name, component, labels)
	out[tagPlacement] = placement
	out[tagLogical] = logical
	return out
}

// logicalFromTags recovers the logical name a resource was provisioned for,
// falling back to the physical name when the tag is absent.
func logicalFromTags(tags map[string]string, physical string) string {
	if name := tags[tagLogical]; name != "" {
		return name
	}
	return physical
}

// placementFromTags recovers the placement a resource was provisioned into,
// falling back to the configured default for a resource written before the tag
// existed.
func (p *Provider) placementFromTags(tags map[string]string) compute.Placement {
	if name := tags[tagPlacement]; name != "" {
		return compute.Placement{Name: name}
	}
	return compute.Placement{Name: p.cfg.DefaultPlacement}
}
