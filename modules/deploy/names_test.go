// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestOnlyAnHTTPSURLOnAnAllowedHostIsAccepted generates its population rather
// than listing cases, and generates it so that it straddles the boundary the
// property is about: every combination below differs from an acceptable URL in
// exactly one respect, so a checker that got one dimension right and dropped
// another cannot pass.
//
// The three things being defended against are the source's own list
// (build.go:100-103): request forgery against something the platform can reach,
// injection through a version-control transport, and handing credentials to a
// server somebody else runs.
func TestOnlyAnHTTPSURLOnAnAllowedHostIsAccepted(t *testing.T) {
	t.Parallel()
	allowed := []string{"code.example.test"}

	// Each dimension's first entry is the acceptable value, so the all-firsts
	// combination is the one URL that must be accepted and every other
	// combination must be refused.
	schemes := []string{"https", "http", "git", "ssh", "file", "javascript"}
	hosts := []string{"code.example.test", "code.example.test.evil.test", "evil.test",
		"CODE.EXAMPLE.TEST.evil.test", "169.254.169.254", "127.0.0.1", "[::1]", "localhost"}
	userinfos := []string{"", "oauth2:ghp_exampletoken@", "user@"}
	ports := []string{"", ":8443", ":22", ":443"}

	var accepted, refused int
	for si, scheme := range schemes {
		for hi, host := range hosts {
			for ui, userinfo := range userinfos {
				for pi, port := range ports {
					// Port 443 is the default and is accepted, so it is not a
					// deviation; every other index being zero still means "the
					// acceptable URL".
					deviates := si != 0 || hi != 0 || ui != 0 || (pi != 0 && port != ":443")
					raw := fmt.Sprintf("%s://%s%s%s/team/repo", scheme, userinfo, host, port)

					got, err := ValidateSourceURL(raw, allowed)
					switch {
					case deviates && err == nil:
						t.Errorf("accepted %q as %q", raw, got)
					case deviates:
						refused++
						if !errors.Is(err, ErrSourceRefused) {
							t.Errorf("%q was refused as something other than a refused source: %v", raw, err)
						}
						// A refusal must not echo credentials back into whatever
						// reads it.
						if strings.Contains(err.Error(), "ghp_exampletoken") {
							t.Errorf("the refusal for %q repeats the embedded credential: %v", raw, err)
						}
					case err != nil:
						t.Errorf("refused the acceptable URL %q: %v", raw, err)
					default:
						accepted++
					}
				}
			}
		}
	}
	// Non-emptiness in both directions. A generator that produced only
	// deviations would pass the loop above having never accepted anything, and
	// one that produced no deviations would have checked nothing.
	if accepted == 0 {
		t.Fatal("no combination was accepted, so this test cannot tell a refusal from a rejection of everything")
	}
	if refused == 0 {
		t.Fatal("no combination was refused, so this test asserts nothing")
	}
	t.Logf("%d accepted, %d refused, over %d combinations",
		accepted, refused, len(schemes)*len(hosts)*len(userinfos)*len(ports))
}

// TestControlCharactersAreRefusedRawAndEncoded. Both spellings, because a
// checker that handles one is a checker somebody rewrites their URL to get past.
func TestControlCharactersAreRefusedRawAndEncoded(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://code.example.test/team/repo\n",
		"https://code.example.test/team/repo\r\n",
		"https://code.example.test/team/repo\x00",
		"https://code.example.test/team/repo%0aX",
		"https://code.example.test/team/repo%0DX",
		"https://code.example.test/team/repo%00",
	} {
		if _, err := ValidateSourceURL(raw, []string{"code.example.test"}); !errors.Is(err, ErrSourceRefused) {
			t.Errorf("accepted %q: %v", raw, err)
		}
	}
}

// TestAnEmptyAllowlistRefusesEverything is the fail-closed reading of "unset".
func TestAnEmptyAllowlistRefusesEverything(t *testing.T) {
	t.Parallel()
	for _, hosts := range [][]string{nil, {}} {
		if _, err := ValidateSourceURL("https://code.example.test/team/repo", hosts); err == nil {
			t.Errorf("an empty allowlist accepted a URL")
		}
	}
}

// TestTheAcceptedURLIsCanonicalised, so that two spellings of one repository do
// not become two.
func TestTheAcceptedURLIsCanonicalised(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://CODE.EXAMPLE.TEST/team/repo",
		"https://code.example.test/team/repo/",
		"https://code.example.test:443/team/repo",
	} {
		got, err := ValidateSourceURL(raw, []string{"code.example.test"})
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if !strings.HasPrefix(got, "https://code.example.test") || strings.HasSuffix(got, "/") {
			t.Errorf("%q canonicalised to %q", raw, got)
		}
	}
}

// TestResourceNamesAreInjective is the property the source did not have.
//
// Its sanitiser mapped every character outside a small set to a hyphen, so
// "my app" and "my-app" produced one ECS service, one IAM role, one security
// group and one bucket between them. The construction here is a refusal rather
// than a fold, so the property is a consequence of the construction — and this
// is the test that says so, over a population containing the exact pairs the
// fold collapsed.
func TestResourceNamesAreInjective(t *testing.T) {
	t.Parallel()
	// Built from the separators the grammar allows rather than written out, so
	// the population is the separators and not a list somebody typed — and so
	// that no dotted pair appears as a whole string literal, which the
	// repository's disclosure scanner reads as a hostname. Restructuring the
	// data is the right answer to that; loosening the scanner is not.
	var ids []string
	for _, sep := range []string{"-", "_", "."} {
		ids = append(ids, "my"+sep+"app", "a"+sep+"b"+sep+"c")
	}
	ids = append(ids, "myapp", "MyApp", "myApp", "app1", "app2")
	seen := map[string]string{}
	for _, id := range ids {
		name, err := resourceName("apphub", &Application{ID: id})
		if err != nil {
			t.Errorf("identifier %q was refused: %v", id, err)
			continue
		}
		if prev, clash := seen[name]; clash {
			t.Errorf("identifiers %q and %q both produce resource name %q, so two applications "+
				"would share every resource", prev, id, name)
		}
		seen[name] = id
	}
	if len(seen) != len(ids) {
		t.Errorf("named %d of %d identifiers", len(seen), len(ids))
	}
}

// TestAnIdentifierThatWouldHaveToBeFoldedIsRefused. This is the other half: the
// injectivity above only holds because nothing is folded, so an identifier that
// cannot be used verbatim has to be refused rather than repaired.
func TestAnIdentifierThatWouldHaveToBeFoldedIsRefused(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		"my app", "my/app", "-leading", "trailing-", "my--app", "", "app!", "app\n", "app:1",
	} {
		if name, err := resourceName("apphub", &Application{ID: id}); err == nil {
			t.Errorf("identifier %q was accepted as %q", id, name)
		} else if !errors.Is(err, ErrInvalidApplication) {
			t.Errorf("identifier %q refused as something else: %v", id, err)
		}
	}
	// And an identifier long enough to overflow the name budget, which is a
	// refusal an operator should get once rather than on every deploy.
	long := strings.Repeat("a", maxResourceName)
	if _, err := resourceName("apphub", &Application{ID: long}); err == nil {
		t.Error("an identifier that overflows every provider's name limit was accepted")
	}
}

// TestARenamedApplicationKeepsItsResources. The source derived every resource
// name from the display name, so renaming an application orphaned everything
// the previous deploy had created.
func TestARenamedApplicationKeepsItsResources(t *testing.T) {
	t.Parallel()
	before, err := resourceName("apphub", &Application{ID: "app-1", Name: "Reports"})
	if err != nil {
		t.Fatalf("resourceName: %v", err)
	}
	after, err := resourceName("apphub", &Application{ID: "app-1", Name: "Quarterly reports"})
	if err != nil {
		t.Fatalf("resourceName: %v", err)
	}
	if before != after {
		t.Errorf("renaming the application moved its resources from %q to %q", before, after)
	}
}
