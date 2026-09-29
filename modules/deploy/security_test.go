// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
)

// The credential-egress tests.
//
// Each one has a control that establishes the material was there to be found,
// because a scan of a channel that could never have carried it is a scan that
// reports success honestly and means nothing. That failure has already happened
// on this project: a credential-egress check passed immediately because the
// runner it scanned wrote only its own arguments.

// hostileDeploy runs a deploy against a provider carrying the given defects,
// arranged so that the database provisioning fails *after* the administrative
// password has been generated and stored. It returns the error, the saved
// record and the password's plaintext.
//
// The failure is provoked with an engine version the provider does not offer,
// which is a validation failure — not a failure to store the secret — so the
// password exists, the store holds it, and the provider's error is the channel
// under test. Keeping the hostility on one channel matters: a fixture that
// failed for two reasons at once would be testing whichever one fired first.
func hostileDeploy(t *testing.T, defects ...fake.Defect) (*Application, string, error) {
	t.Helper()
	ctx := context.Background()
	p := newTestProvider(t, defects...)
	app := testApplication()
	app.Bucket = Bucket{}
	app.Routes = nil
	app.Database.EngineVersion = "1999"
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	_, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a database with an engine version the provider does not offer was provisioned")
	}
	saved := store.saved(app.ID)
	ref, ok := saved.Artifacts.Secrets[EnvDatabasePassword]
	if !ok {
		t.Fatalf("the password was not stored before provisioning, so this fixture cannot " +
			"produce the material it is looking for. The interface requires the store to happen " +
			"first, precisely so a provisioning failure leaves a recoverable password")
	}
	secrets, serr := p.Secrets()
	if serr != nil {
		t.Fatalf("Secrets: %v", serr)
	}
	value, gerr := secrets.Get(ctx, ref)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	plaintext := compute.RevealSecret(value)
	if plaintext == "" {
		t.Fatal("the stored password is empty, so every search for it below succeeds vacuously")
	}
	return saved, plaintext, err
}

// TestTheHostileProviderReallyLeaks is the control. Without it, the test below
// is a scan of a channel that never carried the material.
func TestTheHostileProviderReallyLeaks(t *testing.T) {
	t.Parallel()
	_, plaintext, err := hostileDeploy(t, fake.DefectSecretInError)
	if !strings.Contains(err.Error(), plaintext) {
		t.Fatalf("the provider configured to interpolate the administrative password into its "+
			"error did not do so, so the assertion in the next test is over a channel that "+
			"cannot carry it. Error was: %v", err)
	}

	// And the other direction: a conformant provider does not.
	_, cleanText, clean := hostileDeploy(t)
	if strings.Contains(clean.Error(), cleanText) {
		t.Errorf("a conformant provider put the administrative password in its error: %v", clean)
	}
}

// TestNoDurableRecordCarriesCredentialMaterial is the assertion the control
// above makes meaningful: a provider's error may carry anything, and this
// module must not turn it into an artifact somebody keeps.
//
// The whole saved record is searched, normalised for nothing, so a field added
// to [Application] later is covered by construction rather than by somebody
// remembering to add it here.
func TestNoDurableRecordCarriesCredentialMaterial(t *testing.T) {
	t.Parallel()
	saved, plaintext, _ := hostileDeploy(t, fake.DefectSecretInError)

	record := deepRender(reflect.ValueOf(saved))
	if strings.Contains(record, plaintext) {
		t.Errorf("the persisted application record carries the administrative password. The "+
			"record was:\n%s", record)
	}
	// The failure still has to be diagnosable, or the safe answer is to store
	// nothing and this test would pass on a module that recorded no failure at
	// all.
	if saved.Status != StatusFailed {
		t.Errorf("status = %q, want %q", saved.Status, StatusFailed)
	}
	if saved.FailedStep == "" {
		t.Error("no step was recorded, so a reader is told nothing about where the deploy stopped")
	}
	if saved.FailureClass == "" {
		t.Error("no failure class was recorded")
	}
}

// TestEveryFailureClassIsReachableAndDistinct. classify's answer is what a
// record keeps, so an entry that no error reaches is a classification nobody
// will ever see, and two entries that collapse are a distinction the record
// does not make.
func TestEveryFailureClassIsReachableAndDistinct(t *testing.T) {
	t.Parallel()
	if len(failureClasses) == 0 {
		t.Fatal("no failure classes, so this test asserts nothing")
	}
	seen := map[string]error{}
	for _, c := range failureClasses {
		if prev, dup := seen[c.class]; dup {
			t.Errorf("class %q is produced by both %v and %v", c.class, prev, c.sentinel)
		}
		seen[c.class] = c.sentinel
		if got := classify(c.sentinel); got != c.class {
			t.Errorf("classify(%v) = %q, want %q. An earlier entry matches it, so the record "+
				"would name the wrong cause", c.sentinel, got, c.class)
		}
	}
	if got := classify(errString("something else entirely")); got != "unclassified" {
		t.Errorf("classify of an unrelated error = %q, want %q", got, "unclassified")
	}
	if got := classify(nil); got != "unclassified" {
		t.Errorf("classify(nil) = %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestTheSubstrateRenderingNeverCarriesSecretMaterial scans everything the
// provider put into its substrate after a successful deploy — the analogue of a
// task definition, a pod spec or a build log, which is what an operator, a
// support engineer or an audit log can see.
//
// The control is the fake's own defect for the same channel: with it, the scan
// finds the material; without it, it does not. A scan that cannot go red is not
// a scan.
func TestTheSubstrateRenderingNeverCarriesSecretMaterial(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, defects ...fake.Defect) (string, string) {
		t.Helper()
		ctx := context.Background()
		p := newTestProvider(t, defects...)
		app := testApplication()
		app.Bucket = Bucket{}
		app.Routes = nil
		store := newMemStore(app)
		m, _, _ := newTestModule(t, p, store, testConfig())
		if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		secrets, err := p.Secrets()
		if err != nil {
			t.Fatalf("Secrets: %v", err)
		}
		value, err := secrets.Get(ctx, store.saved(app.ID).Artifacts.Secrets[EnvDatabasePassword])
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		return strings.Join(rendered(t, p), "\n"), compute.RevealSecret(value)
	}

	// Control: a provider that prints secret values in its own listing.
	leaky, leakyText := run(t, fake.DefectSecretValueInStoreListing)
	if !strings.Contains(leaky, leakyText) {
		t.Fatalf("the provider configured to print secret values did not, so the scan below " +
			"searches a channel that cannot carry the material")
	}

	clean, cleanText := run(t)
	if strings.Contains(clean, cleanText) {
		t.Errorf("the administrative password reached the substrate rendering:\n%s", clean)
	}
	// And the workload really does receive it, by reference, or the scan above
	// is clean because nothing was wired.
	if !strings.Contains(clean, EnvDatabasePassword) {
		t.Errorf("the workload was not given the database password at all:\n%s", clean)
	}
}

// TestEveryByteValueIsEitherRejectedOrFoldedWithoutBias states the rejection
// rule as what it is — a deterministic property of which byte values may
// contribute — and quantifies over the whole byte space rather than sampling
// the output and looking for a skew.
//
// The first version of this test did sample, with a bound loose enough not to
// flake, and the mutation it existed to catch went straight past it: the naive
// modulo makes eight of sixty-two symbols about 25% more likely, and no bound
// that survives ordinary noise at a test's sample size separates that from it.
// A count was never the property.
func TestEveryByteValueIsEitherRejectedOrFoldedWithoutBias(t *testing.T) {
	t.Parallel()
	// A source handing out consecutive byte values and wrapping, so the
	// population is the byte space rather than whatever random sampling
	// produced. It starts just below the rejection limit deliberately: a source
	// starting at zero emits thirty-two symbols before it ever reaches a byte
	// the rule rejects, so the property would never have applied. The
	// population has to straddle the boundary the property is about.
	const start = byte(passwordByteLimit - 4)
	next := start
	source := func(buf []byte) (int, error) {
		for i := range buf {
			buf[i] = next
			next++
		}
		return len(buf), nil
	}
	v, err := generatePasswordFrom(source)
	if err != nil {
		t.Fatalf("generatePasswordFrom: %v", err)
	}
	got := compute.RevealSecret(v)
	if len(got) != passwordLength {
		t.Fatalf("length = %d, want %d", len(got), passwordLength)
	}

	// The expected output, computed from the rule rather than from the
	// implementation: the accepted byte values in order, folded.
	var want []byte
	var offered, rejected int
	for b := int(start); len(want) < passwordLength; b = (b + 1) % 256 {
		offered++
		if b >= passwordByteLimit {
			rejected++
			continue
		}
		want = append(want, passwordAlphabet[b%len(passwordAlphabet)])
	}
	if rejected == 0 {
		t.Fatal("no byte value was rejected over the range this test drove, so the property " +
			"being asserted never applied")
	}
	if got != string(want) {
		t.Errorf("a byte at or above the rejection limit contributed a symbol.\n got %q\nwant %q",
			got, string(want))
	}
	t.Logf("%d byte value(s) offered, %d rejected, %d symbols emitted", offered, rejected, len(want))

	// And the properties the rule is for: the alphabet is closed, and two
	// passwords from the real source differ.
	real1, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	real2, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if compute.RevealSecret(real1) == compute.RevealSecret(real2) {
		t.Error("two generated passwords are identical")
	}
	for _, r := range compute.RevealSecret(real1) {
		if !strings.ContainsRune(passwordAlphabet, r) {
			t.Errorf("password contains %q, which is outside the alphabet", r)
		}
	}

	// A failing source is an error, not a short or predictable password.
	if _, err := generatePasswordFrom(func([]byte) (int, error) {
		return 0, errString("no entropy")
	}); err == nil {
		t.Error("a failing entropy source produced a password")
	}
}

// TestTheResultCarriesNoMaterial. The Result is serialised to JSON and returned
// to a caller, so it is a channel like any other.
func TestTheResultCarriesNoMaterial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	result, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	value, err := secrets.Get(ctx, store.saved(app.ID).Artifacts.Secrets[EnvDatabasePassword])
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	rendered := deepRender(reflect.ValueOf(result))
	if strings.Contains(rendered, compute.RevealSecret(value)) {
		t.Errorf("the result carries the administrative password: %s", rendered)
	}
	if !strings.Contains(rendered, app.ID) {
		t.Errorf("the result names nothing about the application, so the search above is over "+
			"an empty result: %s", rendered)
	}
}

// TestABucketIsNeverGrantedMoreThanTheRecordAsksFor drives the grant through
// the substrate's own access check rather than comparing the level this module
// passed with the level it meant to pass.
func TestABucketIsNeverGrantedMoreThanTheRecordAsksFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		level     compute.AccessLevel
		canWrite  bool
		levelName string
	}{
		{compute.AccessRead, false, "read"},
		{compute.AccessReadWrite, true, "read-write"},
	} {
		t.Run(tc.levelName, func(t *testing.T) {
			t.Parallel()
			p := newTestProvider(t)
			app := testApplication()
			app.Database = Database{}
			app.Routes = nil
			app.Bucket = Bucket{Kind: BucketStandard, Access: tc.level}
			store := newMemStore(app)
			m, _, _ := newTestModule(t, p, store, testConfig())
			if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			saved := store.saved(app.ID)

			// Reading is granted at both levels, and asserting it is what makes
			// the write assertion meaningful: without it, a grant that did
			// nothing at all would satisfy the read-only case.
			if err := p.Harness().Read(ctx, saved.Artifacts.Bucket, saved.Artifacts.Identity); err != nil {
				t.Errorf("the workload cannot read its own bucket at level %q: %v", tc.level, err)
			}
			err := p.Harness().Write(ctx, saved.Artifacts.Bucket, saved.Artifacts.Identity)
			if tc.canWrite && err != nil {
				t.Errorf("the workload cannot write its own bucket at level %q: %v", tc.level, err)
			}
			if !tc.canWrite && err == nil {
				t.Errorf("a read-only application can write its bucket")
			}
			// And nobody else can, which is the half a grant test usually
			// forgets.
			if err := p.Harness().AnonymousRead(ctx, saved.Artifacts.Bucket); err == nil {
				t.Error("the application's bucket is readable without an identity")
			}
		})
	}
}
