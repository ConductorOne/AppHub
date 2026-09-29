// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// The function port's three physical-name mappings, as a table so that every
// property below is quantified over all of them rather than asserted about
// whichever one a case happened to name.
//
// This is the shape the two earlier naming defects were missed by: the test that
// preceded them named three cases and passed while two whole classes were live.
// A grammar and a limit are what distinguish these three mappings, so the table
// carries a grammar and a limit and every property is checked against both.
type nameMapping struct {
	what    string
	limit   int
	render  func(p *Provider, logical string) (string, error)
	legal   func(string) bool
	grammar string
}

func functionNameMappings() []nameMapping {
	return []nameMapping{
		{
			what:    "Lambda function name",
			limit:   maxLambdaFunctionName,
			render:  (*Provider).functionName,
			legal:   lambdaFunctionName.MatchString,
			grammar: `[a-zA-Z0-9_-]`,
		},
		{
			what:  "ELBv2 name",
			limit: maxELBName,
			render: func(p *Provider, logical string) (string, error) {
				return p.endpointName(logical)
			},
			legal:   elbName.MatchString,
			grammar: `[a-zA-Z0-9-], not beginning or ending with a hyphen`,
		},
		{
			// The same mapping as the ELBv2 one, checked against the *other*
			// substrate's grammar. One name now serves the load balancer, the
			// target group and the security group (see [Provider.endpointName]
			// for why teardown requires that), so the property to establish is
			// that its output is legal on both. Two entries over one renderer is
			// the point, not a duplication.
			what:  "endpoint name, as a security group name",
			limit: maxELBName,
			render: func(p *Provider, logical string) (string, error) {
				return p.endpointName(logical)
			},
			legal:   endpointSecurityGroupName.MatchString,
			grammar: `EC2's security group name alphabet`,
		},
	}
}

// TestTheFunctionPortsNamesAreInjective is the class test the supervisor
// addendum asks for, applied to this port's own mappings.
//
// It reuses [injectivityCorpus] rather than inventing a second corpus, because
// the corpus is where the adversarial input lives and two corpora drift. The
// property is the same one sentence: *for any two distinct logical names, two
// distinct physical names* — and it is quantified over pairs, over three
// grammars, and over three prefixes.
//
// A collision here is not a naming annoyance. Two endpoints resolving to one
// load balancer means one application's traffic reaching another's function, and
// both objects carry this platform's ownership tag with the same component, so
// [checkOwned] cannot tell them apart. That is the same consequence the shared
// mapping's own test states for IAM roles, one layer up.
func TestTheFunctionPortsNamesAreInjective(t *testing.T) {
	t.Parallel()

	for _, m := range functionNameMappings() {
		for _, prefix := range namingPrefixes(m.limit) {
			t.Run(fmt.Sprintf("%s/prefix=%d", strings.ReplaceAll(m.what, " ", "-"), len(prefix)), func(t *testing.T) {
				t.Parallel()
				p := namingProvider(t, prefix)
				seen := map[string]string{}
				rendered := 0
				for _, name := range injectivityCorpus(t, prefix, m.limit, markerDoubleDash) {
					got, err := m.render(p, name)
					if err != nil {
						// A refusal is a legal answer and collides with nothing.
						continue
					}
					rendered++
					if len(got) > m.limit {
						t.Errorf("%s: %q rendered %d characters, over the limit of %d",
							m.what, name, len(got), m.limit)
					}
					if first, dup := seen[got]; dup {
						t.Errorf("COLLISION in the %s mapping: %q and %q both resolve to %q. Two "+
							"endpoints would share one load balancer, both carrying this "+
							"platform's ownership tag with the same component, so checkOwned "+
							"cannot tell them apart", m.what, first, name, got)
						continue
					}
					seen[got] = name
				}
				// A derivation returning nothing passes every check over it, so
				// the non-emptiness is asserted rather than assumed. This is the
				// contract's rule 7 applied to a test rather than to an audit.
				if rendered < 10 {
					t.Fatalf("%s: only %d names rendered, so this test proved almost nothing; "+
						"either the corpus shrank or every name is being refused", m.what, rendered)
				}
			})
		}
	}
}

// TestTheFunctionPortsNamesAreLegalOnTheirSubstrate is the defect this port
// found in the shared mapping, stated as a property.
//
// The shared [sanitize] appends [digestMarker], a full stop, and argues
// correctly that a full stop cannot survive [notAllowed]. It is illegal in all
// three grammars this port writes into. So a name that gets digested — which is
// any name carrying punctuation, mixed case, or length — would be rejected by
// the AWS API, while every plain lowercase name works.
//
// The property is checked on the *finished* name against the substrate's own
// grammar, which is where the check has to be: the marker mistake is invisible
// to any check on a step that built the name, and it is exactly the "verify at
// the resolution the failure lives at" shape.
func TestTheFunctionPortsNamesAreLegalOnTheirSubstrate(t *testing.T) {
	t.Parallel()

	for _, m := range functionNameMappings() {
		for _, prefix := range namingPrefixes(m.limit) {
			t.Run(fmt.Sprintf("%s/prefix=%d", strings.ReplaceAll(m.what, " ", "-"), len(prefix)), func(t *testing.T) {
				t.Parallel()
				p := namingProvider(t, prefix)
				digested := 0
				for _, name := range injectivityCorpus(t, prefix, m.limit, markerDoubleDash) {
					got, err := m.render(p, name)
					if err != nil {
						continue
					}
					if !m.legal(got) {
						t.Errorf("%s: %q rendered %q, which is not legal (%s). This is the marker "+
							"defect: the shared mapping's digest marker is a full stop and this "+
							"substrate does not admit one", m.what, name, got, m.grammar)
					}
					if strings.Contains(got, digestMarker) {
						t.Errorf("%s: %q rendered %q, which contains the shared digest marker %q; "+
							"this mapping must use %q",
							m.what, name, got, digestMarker, markerDoubleDash)
					}
					if strings.Contains(got, markerDoubleDash) {
						digested++
					}
				}
				// If nothing in the corpus took the digested path, this test
				// would pass without ever exercising the marker — which is the
				// vacuous-green shape the whole project is careful about.
				if digested == 0 {
					t.Fatalf("%s: no name in the corpus took the digested path, so the marker was "+
						"never exercised and this test proved nothing about it", m.what)
				}
			})
		}
	}
}

// TestADigestedNameCannotCollideWithAnUndigestedOne states the marker's own
// property directly, rather than relying on the corpus to contain a witness.
//
// The argument in [markerDoubleDash] is that an undigested physical name
// contains no "--" and a digested one contains exactly one, so the two are
// disjoint sets of strings. That is checkable as a property and it is stronger
// than any corpus: a corpus can only show that the pairs in it do not collide.
func TestADigestedNameCannotCollideWithAnUndigestedOne(t *testing.T) {
	t.Parallel()

	p := namingProvider(t, "apphub-")
	for _, m := range functionNameMappings() {
		t.Run(strings.ReplaceAll(m.what, " ", "-"), func(t *testing.T) {
			t.Parallel()
			for _, name := range injectivityCorpus(t, "apphub-", m.limit, markerDoubleDash) {
				got, err := m.render(p, name)
				if err != nil {
					continue
				}
				if n := strings.Count(got, markerDoubleDash); n > 1 {
					t.Errorf("%s: %q rendered %q with %d occurrences of the marker; the split has "+
						"to be unique for a digested name to determine its own head and digest",
						m.what, name, got, n)
				}
			}
		})
	}
}

// TestAnOperatorPrefixCannotForgeTheMarker is the construction-over-check half.
//
// The disjointness argument depends on the prefix containing no "--", and a
// prefix is the one part of a physical name that does not pass through
// [notAllowed]. So the prefix is validated at construction, and this pins that:
// a prefix that could forge the marker is refused by [New] rather than producing
// a name that collides.
//
// This is the shape the contract prefers — a construction that cannot express
// the violation, rather than a check that notices one — applied at the only
// place the input enters.
func TestAnOperatorPrefixCannotForgeTheMarker(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prefix  string
		refused bool
	}{
		{"apphub-", false},
		{"apphub", false},
		{"", false},
		{"a1-b2-", false},
		// The forgeable ones.
		{"apphub--", true},
		{"on--sight-", true},
		// And the ones the grammar refuses for other reasons, which matter
		// because a prefix that is not lowercase alphanumeric would also reach
		// the substrate.
		{"AppHub-", true},
		{"apphub_", true},
		{"apphub.", true},
		{"apphub/", true},
	} {
		t.Run(fmt.Sprintf("prefix=%q", tc.prefix), func(t *testing.T) {
			t.Parallel()
			err := validateNamePrefix("test", tc.prefix)
			switch {
			case tc.refused && err == nil:
				t.Fatalf("prefix %q was accepted; a prefix containing the digest marker collapses "+
					"the digested and undigested name sets back together", tc.prefix)
			case !tc.refused && err != nil:
				t.Fatalf("prefix %q was refused with %v, and it is a legal one", tc.prefix, err)
			}
		})
	}
}

// TestTheEndpointNameIsLegalOnBothSubstrates pins the two claims that let one
// name serve three objects.
//
// Both are claims about *this file's own constants and regexps* rather than about
// any caller's input, so neither can be exercised by the corpus tests above — and
// both are the kind of claim a future edit to either side falsifies silently.
// [Provider.endpointName] carries a runtime check for the alphabet; this carries
// the ceiling, which has no runtime home because nothing ever sizes a name
// against the looser of the two.
func TestTheEndpointNameIsLegalOnBothSubstrates(t *testing.T) {
	t.Parallel()

	if maxELBName > maxSecurityGroupName {
		t.Fatalf("maxELBName (%d) is now larger than maxSecurityGroupName (%d), so an endpoint "+
			"name sized for ELBv2 can overrun the security group ceiling and one name can no "+
			"longer serve both", maxELBName, maxSecurityGroupName)
	}

	// The alphabet claim, over the corpus rather than over a chosen name, since
	// "elbName's output is always endpointSecurityGroupName-legal" is a statement about
	// every string the mapping can produce.
	p := namingProvider(t, "apphub-")
	checked := 0
	for _, logical := range injectivityCorpus(t, "apphub-", maxELBName, markerDoubleDash) {
		name, err := p.endpointName(logical)
		if err != nil {
			continue
		}
		checked++
		if !endpointSecurityGroupName.MatchString(name) {
			t.Errorf("endpointName(%q) produced %q, which is a legal ELBv2 name and not a legal "+
				"security group name; one name cannot serve both", logical, name)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d names rendered, so this proved almost nothing", checked)
	}
}

// TestAReservedPhysicalNameIsRefused covers the two prefixes the substrates
// reserve, which no amount of injectivity would catch.
func TestAReservedPhysicalNameIsRefused(t *testing.T) {
	t.Parallel()

	// "internal-" is what ELBv2 reserves for its own internal-scheme naming, and
	// "sg-" is what EC2 reserves for a security group identifier. A prefix an
	// operator chose can spell either.
	// Both prefixes are checked against the *same* renderer, because one name
	// now serves both substrates and therefore has to satisfy both reservations.
	p := namingProvider(t, "internal-")
	if _, err := p.endpointName("app"); err == nil {
		t.Fatal("an ELBv2 name beginning \"internal-\" was accepted; ELBv2 reserves it, and " +
			"renaming instead of refusing would break the determinism teardown depends on")
	}
	p = namingProvider(t, "sg-")
	if _, err := p.endpointName("app"); err == nil {
		t.Fatal("an endpoint name beginning \"sg-\" was accepted; the same name is used for the " +
			"security group and EC2 reserves that prefix for an identifier")
	}
}

// namingPrefixes returns the prefixes a mapping's properties are quantified
// over, sized against that mapping's own ceiling.
//
// The third one is the interesting case and it has to be relative rather than a
// literal: the whole point of it is "a prefix long enough that almost nothing
// fits", which is where the head-is-empty branch and the refusal live. A fixed
// twenty-eight-character prefix is that for the 32-character ELBv2 ceiling and
// is unremarkable for the 255-character security group one, so a literal would
// exercise the branch on one mapping and nothing on the other two — and the
// non-emptiness assertion would then fire on the mapping it did reach, which is
// what it is for.
func namingPrefixes(limit int) []string {
	prefixes := []string{"", "apphub-"}
	if room := limit - 25; room > 0 {
		prefixes = append(prefixes, strings.Repeat("p", room)+"-")
	}
	return prefixes
}

// namingProvider builds a provider whose only interesting configuration is the
// two name prefixes, bypassing [New]'s prefix validation so that the naming
// properties can be checked against prefixes [New] would refuse.
//
// Constructed directly rather than through [New] on purpose: two of the tests
// above are about what happens for a prefix New rejects, and going through New
// would make them unreachable.
func namingProvider(t *testing.T, prefix string) *Provider {
	t.Helper()
	return &Provider{
		name: DefaultName,
		cfg: Config{
			Region:           MemoryRegion,
			DefaultPlacement: "default",
			Placements:       map[string]PlacementConfig{"default": {}},
			Function:         &FunctionConfig{NamePrefix: prefix, Runtimes: []string{"provided.al2023"}},
			Endpoint:         &EndpointConfig{NamePrefix: prefix},
		},
		caps: compute.NewCapabilitySet(compute.CapFunction, compute.CapFunctionEndpoint),
	}
}
