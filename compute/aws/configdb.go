// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// RelationalConfig configures the Aurora-backed [compute.RelationalProvisioner].
type RelationalConfig struct {
	// NamePrefix is prepended to every cluster, instance, subnet-group and
	// security-group name this port creates, e.g. "apphub-".
	//
	// The source system hardcodes a product name (container.go:265-267,
	// database.go). A hardcoded prefix in a public repository is a deployment
	// identifier compiled into a library, so it is configuration; empty is
	// legal and means the resource is named after the caller's logical name
	// alone.
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// EngineVersions is the set of major engine versions this deployment will
	// provision, per engine, e.g. {compute.EnginePostgres: {"15", "16"}}.
	//
	// Required and non-empty: a provider that offered no version could satisfy
	// no spec, and one that defaulted to "whatever RDS has" would substitute a
	// major version the application's schema may not run on. The interface is
	// explicit that a provider must reject a version it cannot supply rather
	// than substitute a different one, and the honest way to know what it can
	// supply is to be told.
	//
	// It is operator configuration rather than a DescribeDBEngineVersions call
	// for the same reason [PlacementConfig.VPC] is: an account-wide fact an
	// operator has is better supplied than recovered by a lookup that fails as
	// an AWS problem.
	EngineVersions map[compute.SQLEngine][]string `yaml:"engineVersions" json:"engineVersions"`

	// ACUsPerUnit converts one abstract [compute.CapacityRange] unit into
	// Aurora Capacity Units. Zero means [DefaultACUsPerUnit].
	//
	// The mapping is a translation and this is where it is written down, per
	// [compute.CapacityRange]. It is configurable because an ACU is a billing
	// construct whose price and performance change, and an operator who has
	// measured their own workload should not have to patch a constant.
	ACUsPerUnit float64 `yaml:"acusPerUnit" json:"acusPerUnit"`

	// DefaultMaxUnits is the ceiling a spec with no MaxUnits gets. Zero
	// means the lesser of [DefaultRelationalMaxUnits] and MaxCapacityUnits.
	//
	// It exists because [compute.CapacityRange] requires the default ceiling to
	// be finite — an unbounded default is a billing incident — and Aurora's own
	// maximum is 256 ACUs, which is not a number anybody wants to discover on
	// an invoice. An explicit default cannot exceed the operator ceiling.
	DefaultMaxUnits float64 `yaml:"defaultMaxUnits" json:"defaultMaxUnits"`

	// MaxCapacityUnits limits both the requested floor and ceiling, including
	// explicit requests. Zero uses [DefaultRelationalMaxUnits]. Unlike
	// DefaultMaxUnits, this is an operator-enforced ceiling.
	MaxCapacityUnits float64 `yaml:"maxCapacityUnits" json:"maxCapacityUnits"`

	// InstanceClass is the DB instance class for the writer. Empty means
	// [DefaultInstanceClass], which is the serverless class the scaling
	// configuration above only means anything with.
	//
	// A provisioned class is legal and the reason the field exists: an operator
	// who wants a fixed-size instance can have one, and the effective spec then
	// says in [compute.Status.Message] that the capacity range was not honoured.
	InstanceClass string `yaml:"instanceClass" json:"instanceClass"`
}

// KeyValueConfig configures the DynamoDB-backed
// [compute.KeyValueProvisioner].
type KeyValueConfig struct {
	// NamePrefix is prepended to every table name, e.g. "apphub-".
	//
	// The source system hardcodes the same product prefix (container.go:248).
	// Same reasoning as [RelationalConfig.NamePrefix].
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// GrantPolicyName is the *prefix* of the inline IAM policy name a grant is
	// written under, e.g. "apphub-key-value-access".
	//
	// Empty means [DefaultGrantPolicyName]. It is configuration because the
	// policy name is the unit a grant is replaced and revoked by: two providers
	// sharing an account and a policy name would overwrite each other's grants
	// on a role they both touched, and an operator running two providers has to
	// be able to separate them. The source system hardcodes
	// "app-dynamodb-access" (database.go:144).
	//
	// # Why a prefix and not the whole name
	//
	// It was the whole name once, and that was a defect. [compute.Granter] is
	// keyed on the (resource, identity) pair -- last-write-wins on *level*, for
	// one pair -- and PutRolePolicy replaces the whole document under the name
	// it is given. So one fixed name per provider meant a role could hold a
	// grant on exactly one table at a time: granting on a second table silently
	// destroyed the first, and revoking either destroyed both. Both calls
	// returned nil while doing it.
	//
	// The separation this field exists for is between providers, and a prefix
	// still provides it; the table is appended so the unit of replacement is the
	// pair the interface is keyed on. See [KeyValueConfig.grantPolicyName].
	GrantPolicyName string `yaml:"grantPolicyName" json:"grantPolicyName"`
}

// The database defaults.
const (
	// DefaultACUsPerUnit is two Aurora Capacity Units per abstract unit.
	//
	// One unit is documented as "roughly one vCPU with proportionate memory"
	// and one ACU is approximately 2 GiB of memory with the CPU that goes with
	// it, so two ACUs is the closest honest reading. Applied to the source
	// system's own 0.5–4 ACU range (database.go:307-310) it means a caller
	// asking for 0.25–2 units gets exactly what the source provisions.
	DefaultACUsPerUnit = 2.0

	// DefaultRelationalMaxUnits is the finite ceiling a spec with no MaxUnits
	// gets, in abstract units. Two units is four ACUs, which is the source
	// system's ceiling.
	DefaultRelationalMaxUnits = 2.0

	// DefaultInstanceClass is Aurora's serverless instance class.
	DefaultInstanceClass = "db.serverless"

	// DefaultGrantPolicyName is the prefix of the inline policy name a key-value
	// grant is written under. The table follows it; see
	// [KeyValueConfig.GrantPolicyName].
	DefaultGrantPolicyName = "apphub-key-value-access"

	// auroraPostgresEngine is the RDS engine name for Aurora PostgreSQL.
	auroraPostgresEngine = "aurora-postgresql"

	// postgresPort is the port Postgres listens on. It is a protocol constant
	// rather than configuration: a client that guessed differently could not
	// connect.
	postgresPort = 5432

	// minAuroraACU and maxAuroraACU bound Aurora Serverless v2's scaling
	// configuration, and acuStep is the granularity it accepts. A value off the
	// step is refused rather than rounded — see [RelationalConfig.acuRange].
	minAuroraACU = 0.5
	maxAuroraACU = 256.0
	acuStep      = 0.5
)

func (c *RelationalConfig) acusPerUnit() float64 {
	if c.ACUsPerUnit <= 0 {
		return DefaultACUsPerUnit
	}
	return c.ACUsPerUnit
}

func (c *RelationalConfig) defaultMaxUnits() float64 {
	if c.DefaultMaxUnits <= 0 {
		return math.Min(DefaultRelationalMaxUnits, c.maxCapacityUnits())
	}
	return c.DefaultMaxUnits
}

func (c *RelationalConfig) maxCapacityUnits() float64 {
	if c.MaxCapacityUnits == 0 {
		return DefaultRelationalMaxUnits
	}
	return c.MaxCapacityUnits
}

func (c *RelationalConfig) instanceClass() string {
	if strings.TrimSpace(c.InstanceClass) == "" {
		return DefaultInstanceClass
	}
	return c.InstanceClass
}

// engineName maps a [compute.SQLEngine] onto the RDS engine that speaks it.
//
// Only Postgres. Aurora has a MySQL engine and this provider deliberately does
// not offer it: nothing in the source system provisions one, so there is no call
// site to validate the mapping against, and a provider that accepted
// [compute.EngineMySQL] and guessed at the engine name, the port, and the
// version grammar would be asserting a compatibility nobody has tested. The
// refusal is typed and names the engine, so a caller learns the fact rather than
// meeting it as an RDS error.
func (c *RelationalConfig) engineName(e compute.SQLEngine) (string, error) {
	if e == compute.EnginePostgres {
		return auroraPostgresEngine, nil
	}
	return "", fmt.Errorf("%w: engine %q is not one this provider offers; it offers %q "+
		"(Aurora PostgreSQL)", compute.ErrUnsupported, e, compute.EnginePostgres)
}

// versions returns the major versions configured for an engine, sorted.
func (c *RelationalConfig) versions(e compute.SQLEngine) []string {
	out := append([]string(nil), c.EngineVersions[e]...)
	sort.Strings(out)
	return out
}

// checkVersion refuses a spec whose engine version this deployment did not
// declare.
//
// Substituting is not an option and neither is accepting: [compute.RelationalSpec]
// says a provider must reject a version it cannot supply rather than substitute
// a different one, and a major version an application's schema was not written
// for is a data problem rather than a performance one.
func (c *RelationalConfig) checkVersion(e compute.SQLEngine, version string) error {
	have := c.versions(e)
	if version == "" {
		return fmt.Errorf("%w: no engine version named; this provider offers %s for %q, and the "+
			"major version is the caller's choice because a different one may not run the "+
			"application's schema", compute.ErrInvalidSpec, strings.Join(have, ", "), e)
	}
	for _, v := range have {
		if v == version {
			return nil
		}
	}
	return fmt.Errorf("%w: engine version %q is not one this provider offers for %q (it offers %s); "+
		"configure Config.Relational.EngineVersions if this deployment should supply it",
		compute.ErrInvalidSpec, version, e, strings.Join(have, ", "))
}

// acuRange converts an abstract capacity range into Aurora Capacity Units.
//
// # Why an unrepresentable value is refused rather than rounded
//
// Aurora Serverless v2 scales in half-ACU steps between 0.5 and 256. A range
// that lands off the step has to become something, and both roundings are a lie
// the caller cannot see: rounding the floor down can reach a capacity below what
// the workload needs to start, and rounding the ceiling up bills for capacity
// nobody asked for. USOSS-10 made the same call on [compute.RetentionPolicy.MaxAge]
// and USOSS-26 on parameter tiers, which makes this the fourth port in this
// package that refuses rather than rounds.
//
// The floor and the ceiling are separately checked so the error says which one
// is wrong.
func (c *RelationalConfig) acuRange(r compute.CapacityRange) (minACU, maxACU float64, err error) {
	if math.IsNaN(r.MinUnits) || math.IsNaN(r.MaxUnits) || math.IsInf(r.MinUnits, 0) || math.IsInf(r.MaxUnits, 0) ||
		r.MinUnits < 0 || r.MaxUnits < 0 {
		return 0, 0, fmt.Errorf("%w: a capacity range must be finite and nonnegative (%g to %g units)",
			compute.ErrInvalidSpec, r.MinUnits, r.MaxUnits)
	}
	limit := c.maxCapacityUnits()
	if r.MinUnits > limit || r.MaxUnits > limit {
		return 0, 0, fmt.Errorf("%w: relational capacity exceeds the operator limit of %g units",
			compute.ErrInvalidSpec, limit)
	}
	maxUnits := r.MaxUnits
	if maxUnits == 0 {
		maxUnits = c.defaultMaxUnits()
	}
	if r.MinUnits > maxUnits {
		return 0, 0, fmt.Errorf("%w: the capacity floor (%g units) is above the ceiling (%g units)",
			compute.ErrInvalidSpec, r.MinUnits, maxUnits)
	}

	per := c.acusPerUnit()
	minACU = r.MinUnits * per
	if r.MinUnits == 0 {
		// Zero means "the provider's minimum", which for Serverless v2 is half
		// an ACU. It is not zero: a cluster that scaled to nothing would not
		// accept the connection that role provisioning is about to make.
		minACU = minAuroraACU
	}
	maxACU = maxUnits * per

	if err := checkACU("floor", minACU); err != nil {
		return 0, 0, err
	}
	if err := checkACU("ceiling", maxACU); err != nil {
		return 0, 0, err
	}
	return minACU, maxACU, nil
}

func checkACU(which string, acu float64) error {
	switch {
	case acu < minAuroraACU:
		return fmt.Errorf("%w: the capacity %s works out to %g Aurora Capacity Units and the "+
			"smallest Aurora Serverless v2 will run is %g; rounding up would give the caller "+
			"more capacity than they asked to pay for, so the spec is refused instead",
			compute.ErrInvalidSpec, which, acu, minAuroraACU)
	case acu > maxAuroraACU:
		return fmt.Errorf("%w: the capacity %s works out to %g Aurora Capacity Units and the "+
			"largest Aurora Serverless v2 will run is %g", compute.ErrInvalidSpec, which, acu,
			maxAuroraACU)
	case math.Abs(acu/acuStep-math.Round(acu/acuStep)) > 1e-9:
		return fmt.Errorf("%w: the capacity %s works out to %g Aurora Capacity Units and Aurora "+
			"Serverless v2 scales in steps of %g; rounding down can put the floor below what the "+
			"workload needs to start and rounding up bills for capacity nobody asked for, so the "+
			"spec is refused rather than adjusted", compute.ErrInvalidSpec, which, acu, acuStep)
	default:
		return nil
	}
}

// unitsFromACU is the inverse, for reporting the effective spec back.
func (c *RelationalConfig) unitsFromACU(acu float64) float64 {
	return acu / c.acusPerUnit()
}

// grantPolicyName renders the inline IAM policy name a grant on table is
// written under.
//
// The name is a function of the table because [compute.Granter] is keyed on the
// (resource, identity) pair, and an inline policy name is the unit
// PutRolePolicy replaces and DeleteRolePolicy removes. A name that named only
// the provider would make the *role* the unit, so a second grant on a second
// table would replace the first table's document rather than sit beside it --
// which is what [compute.Granter]'s "affects only the pair it names" means the
// other implementations in this repository get by keying their own store on the
// pair ([compute/fake] on grantKey, [compute/k8s] on a per-bucket policy).
//
// It goes through the sanitizer rather than a concatenation for the reason every
// other derived name here does: the result has to be legal in the substrate's
// grammar by construction, and IAM's 128-character ceiling on an inline policy
// name is half DynamoDB's on a table name. The sanitizer's injectivity is what
// makes two tables two policies -- a truncation would let two long table names
// collide back onto one document and reintroduce the clobbering with extra
// steps.
func (c *KeyValueConfig) grantPolicyName(table string) (string, error) {
	return sanitize(c.grantPolicyPrefix()+"-", table, maxInlinePolicyName)
}

// grantPolicyPrefix is the configured prefix, or the default.
func (c *KeyValueConfig) grantPolicyPrefix() string {
	if strings.TrimSpace(c.GrantPolicyName) == "" {
		return DefaultGrantPolicyName
	}
	return strings.TrimSuffix(strings.TrimSpace(c.GrantPolicyName), "-")
}

// validateKeyValueConfig refuses a key-value configuration that cannot render a
// legal grant policy name, at construction rather than at the grant that needed
// one.
//
// [KeyValueConfig.GrantPolicyName] is a prefix and IAM allows 128 characters for
// the whole inline policy name, so a prefix long enough to leave no room for a
// table is a misconfiguration. Caught here it names the field; caught at Grant it
// arrives as a refused grant in the middle of a deploy, which is a worse place to
// learn that a configuration value was too long.
func validateKeyValueConfig(sub *Substrate, cfg Config) error {
	c := cfg.KeyValue
	if c == nil {
		return nil
	}
	if sub.DynamoDB == nil {
		return errors.New("aws: Config.KeyValue is set and Substrate.DynamoDB is nil, so the " +
			"provider would advertise a capability it cannot serve")
	}
	// Any table name will do: the sanitizer's room check is a function of the
	// prefix and the ceiling, not of the name.
	if _, err := c.grantPolicyName("probe"); err != nil {
		return fmt.Errorf("aws: Config.KeyValue.GrantPolicyName: %w", err)
	}
	return nil
}

// validateRelationalConfig refuses a relational configuration that cannot work,
// at construction rather than at the deploy that needed it.
//
// The prefix rule is the load-bearing one and it is not cosmetic. An RDS
// identifier must begin with a letter; a logical application name may begin with
// a digit, and [sanitizeWith] cannot supply the property without breaking
// injectivity. Requiring a letter-led prefix makes every derived identifier legal
// *by construction*, which is the shape this project prefers to a check that
// notices a violation at provisioning time.
func validateRelationalConfig(sub *Substrate, cfg Config) error {
	c := cfg.Relational
	if c == nil {
		return nil
	}
	switch {
	case sub.RDS == nil:
		return errors.New("aws: Config.Relational is set and Substrate.RDS is nil, so the " +
			"provider would advertise a capability it cannot serve")
	case sub.EC2 == nil:
		return errors.New("aws: Config.Relational is set and Substrate.EC2 is nil; a database " +
			"endpoint is unreachable without the security group that fronts it, and this " +
			"provider does not create an endpoint it cannot make reachable")
	case len(c.EngineVersions) == 0:
		return errors.New("aws: Config.Relational.EngineVersions is empty, so every spec would " +
			"be refused; declare the major engine versions this deployment provisions. There is " +
			"no default: a provider that substituted a version the caller did not ask for would " +
			"be making a data-compatibility decision on their behalf")
	case !rdsPrefix.MatchString(c.NamePrefix):
		return fmt.Errorf("aws: Config.Relational.NamePrefix %q cannot produce a legal RDS "+
			"identifier. It must begin with a lowercase letter and hold only lowercase letters, "+
			"digits and single hyphens (it may end in one). It is required, and it is what makes "+
			"the leading-letter rule hold for an application whose own name begins with a digit",
			c.NamePrefix)
	}
	if math.IsNaN(c.ACUsPerUnit) || math.IsInf(c.ACUsPerUnit, 0) || c.ACUsPerUnit < 0 {
		return errors.New("aws: Config.Relational.ACUsPerUnit must be finite and nonnegative")
	}
	if math.IsNaN(c.MaxCapacityUnits) || math.IsInf(c.MaxCapacityUnits, 0) ||
		c.maxCapacityUnits() <= 0 || c.maxCapacityUnits()*c.acusPerUnit() > maxAuroraACU ||
		c.maxCapacityUnits()*c.acusPerUnit() < minAuroraACU {
		return errors.New("aws: Config.Relational.MaxCapacityUnits must be finite, positive and within Aurora's ACU range")
	}
	if math.IsNaN(c.DefaultMaxUnits) || math.IsInf(c.DefaultMaxUnits, 0) ||
		c.DefaultMaxUnits < 0 || c.defaultMaxUnits() > c.maxCapacityUnits() {
		return errors.New("aws: Config.Relational.DefaultMaxUnits must be finite, nonnegative and no greater than MaxCapacityUnits")
	}
	for engine, versions := range c.EngineVersions {
		if _, err := c.engineName(engine); err != nil {
			return fmt.Errorf("aws: Config.Relational.EngineVersions names engine %q: %w", engine, err)
		}
		if len(versions) == 0 {
			return fmt.Errorf("aws: Config.Relational.EngineVersions has no versions for engine "+
				"%q, so every spec naming it would be refused", engine)
		}
		for _, v := range versions {
			if v != majorVersion(v) {
				// A minor pinned in configuration is the failure the interface
				// documents: provisioning breaks the day RDS retires it, and the
				// operator learns from an RDS error rather than from here.
				return fmt.Errorf("aws: Config.Relational.EngineVersions names %q for engine %q, "+
					"which pins a minor version; the interface takes major versions only, because "+
					"pinning a minor makes provisioning fail the day RDS retires it", v, engine)
			}
		}
	}
	// A placement with no VPC or fewer than two subnets cannot hold a database.
	// It is not refused here, because a provider may legitimately have one
	// placement that can and one that cannot; but a provider where *none* can is
	// advertising a capability it can never serve.
	for _, pc := range cfg.Placements {
		if strings.TrimSpace(pc.VPC) != "" && len(pc.Subnets) >= 2 {
			return nil
		}
	}
	return errors.New("aws: Config.Relational is set and no configured placement has a VPC and " +
		"at least two subnets, so every relational spec would be refused; set PlacementConfig.VPC " +
		"and PlacementConfig.Subnets on the placements that can hold a database")
}
