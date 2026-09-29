// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// TestSanitizeIsInjective states the property, quantified over pairs.
//
// The predecessor of this test named three cases and passed while two whole
// classes of collision were live, which is CONTRACT lesson 3 in its exact
// stated form: every gap sat one generalisation away from a test already
// written. The property is one sentence — *for any two distinct logical names,
// sanitize returns two distinct strings* — and this test is that sentence over
// a corpus built to contain every shape known to have broken it.
//
// The corpus is deliberately adversarial rather than representative. It
// includes the two reproductions review supplied, the case variants that extend
// the first one, and the constructed collisions for the truncating path.
func TestSanitizeIsInjective(t *testing.T) {
	t.Parallel()

	// Quantified over the marker as well as the prefix and the limit. The
	// separator became a parameter when S3 bucket names arrived -- "." is
	// TLS-hostile in a bucket name and "--" is illegal in an ECR repository name,
	// so no one string is safe everywhere -- and the whole injectivity argument
	// rests on the marker being unreachable in a lossless name. A marker chosen
	// without that property silently reintroduces the collisions this test
	// exists for, so every marker the package uses is quantified over rather
	// than the one that happened to be first.
	for _, tc := range []struct {
		prefix string
		limit  int
		marker string
	}{
		{"", maxIAMRoleName, digestMarker},
		{"apphub-", maxIAMRoleName, digestMarker},
		{"apphub/", maxECRRepositoryName, digestMarker},
		// A prefix long enough that almost nothing fits, which is where the
		// head-is-empty branch lives.
		{strings.Repeat("p", maxIAMRoleName-25) + "-", maxIAMRoleName, digestMarker},
		// The bucket grammar, at its own limit and with its own separator.
		{"", maxS3BucketName, bucketDigestMarker},
		{"apphub-", maxS3BucketName, bucketDigestMarker},
		{strings.Repeat("p", maxS3BucketName-25) + "-", maxS3BucketName, bucketDigestMarker},
	} {
		t.Run(fmt.Sprintf("prefix=%d/limit=%d/marker=%s", len(tc.prefix), tc.limit, tc.marker), func(t *testing.T) {
			t.Parallel()
			seen := map[string]string{}
			for _, name := range injectivityCorpus(t, tc.prefix, tc.limit, tc.marker) {
				got, err := sanitizeWith(tc.prefix, name, tc.limit, tc.marker)
				if err != nil {
					// A refusal is a legal answer — it is what a prefix with no
					// room for a name gets — and it collides with nothing.
					continue
				}
				if len(got) > tc.limit {
					t.Errorf("sanitize(%q) produced %d characters, over the limit of %d",
						name, len(got), tc.limit)
				}
				if first, dup := seen[got]; dup {
					t.Errorf("COLLISION: %q and %q both resolve to %q. Two applications would "+
						"share one repository or one IAM role, both would carry this platform's "+
						"ownership tag, and the ownership check cannot tell them apart",
						first, name, got)
					continue
				}
				seen[got] = name
			}
		})
	}
}

// injectivityCorpus is the set of logical names the injectivity property is
// quantified over.
//
// Every entry is here because it broke something or is one step from something
// that did. Nothing is here because it looked realistic.
func injectivityCorpus(t *testing.T, prefix string, limit int, marker string) []string {
	t.Helper()
	names := []string{
		// Review's first reproduction: punctuation erased rather than encoded.
		// Six names, one output, no work factor.
		"app-x9", "app_x9", "app.x9", "app  x9", "app!!x9", "app/x9", "app@x9",
		// Case, which is the same class and extends it.
		"App-X9", "APP-X9", "app-X9",
		// Leading and trailing punctuation, which trimming erases.
		"-app-x9", "app-x9-", "--app-x9--", ".app-x9.",
		// Names that are nothing but separators.
		"-", "--", "...", "   ", "!!",
		// Unicode, which was named as an adversarial class and had no input.
		// Every one of these sanitizes to something a caller could also have
		// asked for directly, so they are exactly the shape the verbatim clause
		// has to keep out of its own namespace.
		"caf\u00e9", "cafe", "caf\u00e9-app", "cafe-app",
		"\u0430pp", "app", // Cyrillic a, then Latin
		"\u00c5NGSTR\u00d6M", "angstrom",
		"app\u200bcache", "app-cache", // zero-width space
		"\U0001f600", "\U0001f600\U0001f600",
		// Ordinary ones, which must keep their readable form.
		"app", "app-cache", "a", "app2",
		// Leading digits, added by USOSS-14. They are here rather than in a
		// second corpus because two corpora are two populations and the one
		// nobody extends goes stale. RDS requires an identifier to begin with a
		// letter, so these are the shapes that make the *conjunction* of
		// injectivity and grammar-legality non-trivial — see
		// TestRDSIdentifiersAreInjectiveAndLegal, which quantifies over this same
		// set.
		"9lives", "0", "1-app", "42", "9-lives", "9_lives", "9 lives",
		// Shapes that look like a rendered name under the RDS marker, which is a
		// hyphen rather than a full stop. A hyphen is inside the name alphabet,
		// so these are exactly the strings that would collide with a digested
		// name if the verbatim clause did not exclude a digest tail.
		"app-0123456789abcdef", "app-0123456789ABCDEF", "app-0123456789abcdeff",
		"app-0123456789abcde", "0123456789abcdef",
		// Long enough to truncate, sharing a prefix.
		"app-" + strings.Repeat("y", limit*2) + "-one",
		"app-" + strings.Repeat("y", limit*2) + "-two",
		strings.Repeat("a", limit*3),
		strings.Repeat("Some Very Long Application Name ", 20),
	}

	// Review's second reproduction, and the predecessor's own: a name spelled
	// exactly like another name's rendered form. Both are constructed from the
	// output rather than guessed, so they stay adversarial if the rendering
	// changes.
	for _, seed := range []string{"some-long-application-name", "app-" + strings.Repeat("x", limit*2)} {
		rendered, err := sanitizeWith(prefix, seed, limit, marker)
		if err != nil {
			continue
		}
		body := strings.TrimPrefix(rendered, prefix)
		names = append(names,
			seed,
			// The whole rendered body as a logical name of its own.
			body,
			// And with the marker spelled as the hyphen the old scheme used,
			// which is the collision the marker was introduced to close.
			strings.ReplaceAll(body, marker, "-"),
		)
	}

	// The property is over *distinct* logical names, so the corpus is deduped.
	// Without this the constructed entries collide with the seeds they were
	// built from whenever a seed renders verbatim, and the test reports a
	// collision between a name and itself — which is a bug in the corpus, not
	// in sanitize, and exactly the kind of noise that gets a real finding
	// dismissed.
	seen := map[string]bool{}
	out := names[:0]
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// TestAVerbatimNameKeepsItsShape.
//
// Injectivity is easy to get by digesting everything, and that would make every
// repository and role unreadable. The rule is narrower: a name that survives
// sanitization byte-for-byte is used as it is, and only a name that had to be
// changed carries a digest. This pins the readable half so a future fix for a
// collision cannot quietly digest everything.
func TestAVerbatimNameKeepsItsShape(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"app", "app-cache", "app-x9", "a1", "cf-image-repository-7"} {
		got, err := sanitizeWith("apphub/", name, maxECRRepositoryName, digestMarker)
		if err != nil {
			t.Fatalf("sanitize(%q): %v", name, err)
		}
		if got != "apphub/"+name {
			t.Errorf("sanitize(%q) = %q, want it used verbatim; a name that needed no change "+
				"should not carry a digest", name, got)
		}
	}
	// And the negative half: anything that had to change carries the marker,
	// which is what keeps the two sets disjoint.
	for _, name := range []string{"App-X9", "app_x9", "app.x9", strings.Repeat("a", 400)} {
		got, err := sanitizeWith("apphub/", name, maxECRRepositoryName, digestMarker)
		if err != nil {
			t.Fatalf("sanitize(%q): %v", name, err)
		}
		if !strings.Contains(strings.TrimPrefix(got, "apphub/"), digestMarker) {
			t.Errorf("sanitize(%q) = %q, which carries no digest marker even though the name had "+
				"to be changed; it is therefore in the same set of strings as a verbatim name",
				name, got)
		}
	}
}

// TestAPrefixWithNoRoomIsRefusedRatherThanRendered.
//
// The branch this replaces returned the bare digest, which is an ordinary
// verbatim-shaped name — so it reintroduced the collision the marker exists to
// prevent, inside the branch added to close the previous one. Refusing is the
// honest answer: the operator's prefix is the thing that is wrong, and it is
// named.
func TestAPrefixWithNoRoomIsRefusedRatherThanRendered(t *testing.T) {
	t.Parallel()
	prefix := strings.Repeat("p", maxIAMRoleName-len(digestMarker)-digestLength)
	if _, err := sanitizeWith(prefix, "some-long-application-name", maxIAMRoleName, digestMarker); err == nil {
		t.Error("a prefix leaving no room for a name rendered something anyway")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}

	// And it reaches the caller as a refusal naming the field to change.
	p := &Provider{
		name: "aws",
		cfg:  Config{Identity: IdentityConfig{NamePrefix: prefix}},
	}
	_, err := p.roleName("some-long-application-name")
	if err == nil || !strings.Contains(err.Error(), "Config.Identity.NamePrefix") {
		t.Errorf("roleName refused with %v; an operator reading it cannot tell which field to "+
			"change", err)
	}
}

// TestTruncatedNamesAreStillLegalOnBothSubstrates.
//
// The marker has to be legal in the two grammars this package writes into, and
// a truncated name is exactly where an illegal character would first appear —
// after every short name in the test suite has already passed.
func TestTruncatedNamesAreStillLegalOnBothSubstrates(t *testing.T) {
	t.Parallel()
	p := &Provider{
		name: "aws",
		cfg: Config{
			Registry: &RegistryConfig{NamePrefix: "apphub/"},
			Identity: IdentityConfig{NamePrefix: "apphub-"},
		},
	}
	for _, logical := range []string{
		strings.Repeat("a", 400),
		strings.Repeat("Some Very Long Application Name ", 20),
		strings.Repeat("-", 300) + "app" + strings.Repeat("-", 300),
	} {
		repo, err := p.repositoryName(logical)
		if err != nil {
			t.Errorf("repositoryName(%d chars): %v", len(logical), err)
		} else if len(repo) > maxECRRepositoryName {
			t.Errorf("repositoryName produced %d characters", len(repo))
		}
		role, err := p.roleName(logical)
		if err != nil {
			t.Errorf("roleName(%d chars): %v", len(logical), err)
		} else if len(role) > maxIAMRoleName {
			t.Errorf("roleName produced %d characters", len(role))
		}
	}
}

// TestOwnershipNeedsBothTags.
//
// Every AWS port in this package creates IAM roles, and an IAM role is
// account-global. A check that reads only the ownership tag makes every
// resource apphub owns interchangeable by name — so a role created as a
// cross-account external-access principal could be adopted as a workload
// identity, silently repurposing a trust relationship. USOSS-13's finding.
func TestOwnershipNeedsBothTags(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		tags    map[string]string
		wantErr bool
	}{
		"apphub's own, as the right component": {
			tags:    map[string]string{tagManagedBy: managedByValue, tagComponent: componentIdentity},
			wantErr: false,
		},
		"apphub's own, as a different component": {
			tags:    map[string]string{tagManagedBy: managedByValue, tagComponent: "external-access"},
			wantErr: true,
		},
		"apphub's own, with no component at all": {
			tags:    map[string]string{tagManagedBy: managedByValue},
			wantErr: true,
		},
		"somebody else's": {
			tags:    map[string]string{"created-by": "somebody-else"},
			wantErr: true,
		},
		"nothing at all": {
			tags:    nil,
			wantErr: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := checkOwned(tc.tags, "IAM role", componentIdentity, "apphub-app")
			switch {
			case tc.wantErr && err == nil:
				t.Error("the resource was claimed")
			case tc.wantErr && !isNotOwned(err):
				t.Errorf("refused with %v, want compute.ErrNotOwned", err)
			case !tc.wantErr && err != nil:
				t.Errorf("a resource this platform owns was refused: %v", err)
			}
		})
	}
}

func isNotOwned(err error) bool {
	return err != nil && strings.Contains(err.Error(), compute.ErrNotOwned.Error())
}
