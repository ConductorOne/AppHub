// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// TestEveryInputTypeAndFieldIsClassified is the completeness half, and it
// derives its population the same way [checkApplicability] does: by reaching
// types from [Application] rather than by listing them.
//
// The previous version listed five container types. Review defeated it with a
// nested struct: the outer field was classified, the derived count rose, and
// the nested type's fields stayed outside the population. A count that rises
// without coverage rising is the exact failure the fatal-on-unclassified rule
// exists to prevent, so the list had to go.
func TestEveryInputTypeAndFieldIsClassified(t *testing.T) {
	t.Parallel()
	types, fields := reachableInputSurface(t)
	if len(types) == 0 || len(fields) == 0 {
		t.Fatal("reached no input types or fields, so this test asserts nothing")
	}

	for _, name := range types {
		if _, ruled := wholeTypeDecisions[name]; ruled {
			continue
		}
		var classified bool
		for _, key := range fields {
			if strings.HasPrefix(key, name+".") {
				classified = true
				break
			}
		}
		if !classified {
			t.Errorf("type %s is reached from the application record and has no classified "+
				"fields and no whole-type decision", name)
		}
	}
	for _, key := range fields {
		typeName := key[:strings.Index(key, ".")]
		if _, ruled := wholeTypeDecisions[typeName]; ruled {
			continue
		}
		if _, ok := inputFields[key]; !ok {
			t.Errorf("%s is not classified: nothing says when it applies, so nothing stops a "+
				"record setting it where it means nothing", key)
		}
	}

	// The other direction: a table entry for a field that is no longer reached
	// is an exemption nobody removed.
	reached := map[string]bool{}
	for _, key := range fields {
		reached[key] = true
	}
	for key := range inputFields {
		if !reached[key] {
			t.Errorf("inputFields classifies %q, which is not reachable from Application", key)
		}
	}
	for name := range wholeTypeDecisions {
		if !contains(types, name) {
			t.Errorf("wholeTypeDecisions rules on %q, which is not reachable from Application", name)
		}
	}
	t.Logf("reached %d input type(s) and %d exported field(s) from Application; %d whole-type "+
		"decision(s)", len(types), len(fields), len(wholeTypeDecisions))
}

// reachableInputSurface reaches every struct this package owns from
// [Application] and returns the type names and the "Type.Field" keys.
//
// It is a second implementation of the traversal, deliberately: a test that
// called the production walk would share its bugs, which is the same reason a
// fake that agrees with the code proves nothing about the code. The two agree
// on this tree, and if one grows a blind spot the other reports it.
func reachableInputSurface(tb testing.TB) (types, fields []string) {
	tb.Helper()
	seen := map[reflect.Type]bool{}
	var visit func(reflect.Type)
	visit = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice ||
			rt.Kind() == reflect.Array || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || rt.PkgPath() != packagePath || seen[rt] {
			return
		}
		seen[rt] = true
		types = append(types, rt.Name())
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			fields = append(fields, rt.Name()+"."+f.Name)
			visit(f.Type)
		}
	}
	visit(reflect.TypeOf(Application{}))
	sort.Strings(types)
	sort.Strings(fields)
	return types, fields
}

// TestANestedInputTypeNobodyClassifiedIsFatal is the reproduction from round
// two of review, expressed as a property rather than as that one type.
//
// The mutation is on the tables rather than on a type, because adding a field
// to [Application] from a test is not possible — but withholding the
// classification of a type the walk reaches produces the same state, which is a
// struct the walk meets and has no ruling for.
func TestANestedInputTypeNobodyClassifiedIsFatal(t *testing.T) {
	t.Parallel()
	// Bucket is nested inside Application and its fields are classified. Take
	// them away and the walk must say so rather than descend silently.
	withoutBucket := map[string]condition{}
	for k, v := range inputFields {
		if !strings.HasPrefix(k, "Bucket.") {
			withoutBucket[k] = v
		}
	}
	err := applicability(testApplication(), withoutBucket, wholeTypeDecisions)
	if err == nil {
		t.Fatal("a nested type with no classified fields was accepted")
	}
	for _, want := range []string{"Bucket.Kind", "not classified"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}

	// And a nested type reached only through a SLICE, which is how Route and
	// SecretBinding arrive and is the shape an empty fixture would hide.
	withoutRoute := map[string]condition{}
	for k, v := range inputFields {
		if !strings.HasPrefix(k, "Route.") {
			withoutRoute[k] = v
		}
	}
	bare := minimalApplication() // no routes at all
	if err := applicability(bare, withoutRoute, wholeTypeDecisions); err == nil {
		t.Fatal("an unclassified type reached only through an EMPTY slice was accepted; the " +
			"classification would then depend on the record rather than on the types")
	}

	// The control: with the shipped tables, the same records are accepted.
	if err := checkApplicability(testApplication()); err != nil {
		t.Errorf("the shipped tables refuse the fixture: %v", err)
	}
	if err := checkApplicability(bare); err != nil {
		t.Errorf("the shipped tables refuse the minimal fixture: %v", err)
	}
}

// TestTheWalkDoesNotRuleOnTypesThisPackageDoesNotOwn pins the boundary.
//
// [Application] holds compute values and a time.Time. Classifying their fields
// would be this package ruling on types it does not define, and the ownership
// test is reflect.Type.PkgPath rather than a list of names — so a compute type
// added to the record does not silently demand entries here.
func TestTheWalkDoesNotRuleOnTypesThisPackageDoesNotOwn(t *testing.T) {
	t.Parallel()
	types, _ := reachableInputSurface(t)
	for _, name := range types {
		if name == "" {
			t.Error("an anonymous type was reached")
		}
	}
	// The record really does hold foreign struct types, or the property above
	// is over an empty set.
	var foreign int
	rt := reflect.TypeOf(Application{})
	for i := 0; i < rt.NumField(); i++ {
		ft := rt.Field(i).Type
		if ft.Kind() == reflect.Struct && ft.PkgPath() != packagePath {
			foreign++
		}
	}
	if foreign == 0 {
		t.Fatal("the application record holds no foreign struct fields, so this test asserts nothing")
	}
	for _, name := range types {
		if contains([]string{"Ref", "Resources", "Schedule", "ExpectedAttestation"}, name) {
			t.Errorf("%s belongs to another package and this walk ruled on it", name)
		}
	}
	t.Logf("%d foreign struct field(s) on Application, none descended into", foreign)
}

// A value a field of each kind can take// A value a field of each kind can take, so the population is "every
// classified field" rather than "every field this test knows how to fill".
func nonZero(t *testing.T, f reflect.StructField) reflect.Value {
	t.Helper()
	switch f.Type.Kind() {
	case reflect.String:
		return reflect.ValueOf("set").Convert(f.Type)
	case reflect.Int:
		return reflect.ValueOf(7).Convert(f.Type)
	case reflect.Float64:
		return reflect.ValueOf(1.5).Convert(f.Type)
	case reflect.Bool:
		return reflect.ValueOf(true).Convert(f.Type)
	case reflect.Slice:
		return reflect.MakeSlice(f.Type, 1, 1)
	case reflect.Struct:
		// One non-zero field is enough to make the struct non-zero.
		v := reflect.New(f.Type).Elem()
		for i := 0; i < f.Type.NumField(); i++ {
			if inner := f.Type.Field(i); inner.IsExported() {
				v.Field(i).Set(nonZero(t, inner))
				return v
			}
		}
		t.Fatalf("cannot make %s non-zero: it has no exported fields", f.Type)
	default:
		// Fatal rather than skipped. A field this test cannot fill is a
		// field the property below silently does not cover.
		t.Fatalf("cannot make a %s non-zero; this test would report coverage it does "+
			"not have", f.Type.Kind())
	}
	return reflect.Value{}
}

// TestAVariantFieldSetOutsideItsVariantIsRefused is the behavioural half, and
// it quantifies over the classification table rather than over the three cases
// review reproduced.
//
// For every field whose condition is not unconditional, it builds a record where
// the condition is false, sets the field to a non-zero value, and requires a
// refusal that names the field — before anything is created. A field added to
// the table gets this treatment for free, which is the whole reason the rule is
// a table and not a handful of checks.
func TestAVariantFieldSetOutsideItsVariantIsRefused(t *testing.T) {
	t.Parallel()

	// Where each conditionally-classified struct lives on the record, so a
	// mutation can be written back. Route is reached through a slice and is
	// driven separately; SecretBinding has no conditional field.
	locate := map[string]func(*Application) reflect.Value{
		"Application": func(a *Application) reflect.Value { return reflect.ValueOf(a).Elem() },
		"Source":      func(a *Application) reflect.Value { return reflect.ValueOf(&a.Source).Elem() },
		"Database":    func(a *Application) reflect.Value { return reflect.ValueOf(&a.Database).Elem() },
		"Bucket":      func(a *Application) reflect.Value { return reflect.ValueOf(&a.Bucket).Elem() },
	}

	// The population is every classified field, derived the same way the walk
	// derives it, so a field added to a nested type is driven without anybody
	// adding a case.
	_, allFields := reachableInputSurface(t)
	var driven, skippedForReach int
	for _, key := range allFields {
		cond, known := inputFields[key]
		if !known {
			continue // TestEveryInputTypeAndFieldIsClassified owns that failure.
		}
		// An unconditional field has no "outside its variant" to drive, and an
		// output is not an input at all.
		if cond.name == always.name || cond.name == output.name {
			continue
		}
		typeName := key[:strings.Index(key, ".")]
		fieldName := key[strings.Index(key, ".")+1:]
		at, reachable := locate[typeName]
		if !reachable {
			// Fatal-adjacent on purpose: recorded and asserted below, so a
			// conditional field this test cannot reach is a stated gap rather
			// than a silent one.
			skippedForReach++
			continue
		}
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			// A record on which the condition is false. minimalApplication
			// asks for nothing optional, so every condition in the table is
			// false on it -- which is what lets this loop drive each field
			// outside its variant rather than only the ones that happen not
			// to apply to a richer fixture.
			app := minimalApplication()
			target := at(app)
			f, ok := target.Type().FieldByName(fieldName)
			if !ok {
				t.Fatalf("%s names no field on %s", key, typeName)
			}
			if cond.holds(app, target) {
				t.Fatalf("the baseline already satisfies %q, so this case drives nothing",
					cond.name)
			}
			target.FieldByName(fieldName).Set(nonZero(t, f))

			err := checkApplicability(app)
			if err == nil {
				t.Fatalf("%s was accepted outside %s", key, cond.name)
			}
			if !errors.Is(err, ErrInvalidApplication) {
				t.Errorf("refusal is not an invalid-application failure: %v", err)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("the refusal does not name the field: %v", err)
			}
			// And through the entry point that matters: nothing created.
			p := newTestProvider(t)
			store := newMemStore(app)
			m, _, _ := newTestModule(t, p, store, testConfig())
			if _, err := m.Execute(t.Context(), "", map[string]any{"applicationId": app.ID}); err == nil {
				t.Error("Execute deployed it")
			}
			if r := rendered(t, p); len(r) != 0 {
				t.Errorf("%d resource(s) were created before the refusal: %v", len(r), r)
			}
			if store.saves != 0 {
				t.Errorf("the record was written %d time(s) before the refusal", store.saves)
			}
		})
		driven++
	}
	if driven == 0 {
		t.Fatal("no conditional field was driven, so this test asserts nothing")
	}
	// Exactly one conditional field lives on a type reached through a slice --
	// Route.PublicPaths -- and it has its own test below. Any other is a field
	// this loop silently did not drive, which is the shape that lets a count
	// rise without coverage rising.
	if skippedForReach != 1 {
		t.Errorf("%d conditional field(s) were not driven here; only Route.PublicPaths should "+
			"be, and every other one is coverage this test is claiming and not providing",
			skippedForReach)
	}
	t.Logf("drove %d conditional field(s), 1 driven separately", driven)

	// The other direction, and it is what stops the table above being satisfied
	// by a check that refuses everything: the same fields, set where they DO
	// apply, are accepted.
	for name, app := range map[string]*Application{
		"a service with a relational database and a standard bucket": testApplication(),
		"a scheduled application":                                    testScheduledApplication(),
		"an application that asks for nothing optional":              minimalApplication(),
	} {
		if err := checkApplicability(app); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	zonal := testApplication()
	zonal.Bucket = Bucket{Kind: BucketZonal, Zone: "zone-a"}
	if err := checkApplicability(zonal); err != nil {
		t.Errorf("a zonal bucket carrying a zone was refused: %v", err)
	}
	kv := testApplication()
	kv.Database = Database{Kind: DatabaseKeyValue, PartitionKey: "pk", SortKey: "sk"}
	if err := checkApplicability(kv); err != nil {
		t.Errorf("a key-value table carrying its keys was refused: %v", err)
	}
	auth := testApplication()
	auth.Routes = []Route{{Hostname: "reports", RequireAuth: true, PublicPaths: []string{"/healthz"}}}
	if err := checkApplicability(auth); err != nil {
		t.Errorf("public paths on an authenticated route were refused: %v", err)
	}
}

// TestPublicPathsOnAnUnauthenticatedRouteAreRefused drives the one route-level
// condition, since the loop above cannot reach a slice element.
func TestPublicPathsOnAnUnauthenticatedRouteAreRefused(t *testing.T) {
	t.Parallel()
	app := testApplication()
	app.Routes = []Route{{Hostname: "reports", RequireAuth: false, PublicPaths: []string{"/healthz"}}}
	err := checkApplicability(app)
	if err == nil {
		t.Fatal("paths exempt from an authentication the route does not require were accepted")
	}
	if !strings.Contains(err.Error(), "Route.PublicPaths") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

// TestEveryAccessLevelComputeDefinesIsRuledOn cross-checks this package's
// decided subset against its source, generatively.
//
// [applicationBucketAccess] is a decided population — two of compute's three
// levels are accepted and the third is excluded with a reason — so it is a
// declaration rather than a copy, and it cannot go stale in its SPELLING
// because it names the constants. What it can go stale about is compute
// growing a fourth level nobody ruled on, which would then be neither accepted
// nor excluded and would reach a provider as an unknown string.
//
// The population therefore comes from the type checker over the compute package
// rather than from a list here, for the same reason compute's own sentinel
// derivation does: a syntax walk enumerates the forms it happens to recognise,
// and every property over it is complete with respect to a set the walk chose.
func TestEveryAccessLevelComputeDefinesIsRuledOn(t *testing.T) {
	t.Parallel()
	levels := computeAccessLevels(t)
	if len(levels) < 2 {
		t.Fatalf("the type checker found %d access levels, which cannot be right", len(levels))
	}
	for _, level := range levels {
		if _, ruled := applicationBucketAccess[compute.AccessLevel(level)]; !ruled {
			t.Errorf("compute defines access level %q and this package neither accepts it nor "+
				"excludes it with a reason, so a record asking for it would reach a provider "+
				"as a value nobody ruled on", level)
		}
	}
	// And the reverse: a level this package rules on that compute no longer
	// defines is a decision about something that does not exist.
	defined := map[string]bool{}
	for _, l := range levels {
		defined[l] = true
	}
	for level := range applicationBucketAccess {
		if !defined[string(level)] {
			t.Errorf("this package rules on access level %q, which compute does not define", level)
		}
	}
	// The partition is non-trivial in both directions, or the property above is
	// satisfied by accepting everything or by excluding everything.
	accepted := acceptedBucketAccess()
	if len(accepted) == 0 {
		t.Error("no access level is accepted")
	}
	if len(accepted) == len(applicationBucketAccess) {
		t.Error("every access level is accepted, so the exclusion carries no information")
	}
	t.Logf("compute defines %d access level(s); this package accepts %v", len(levels), accepted)
}

// computeAccessLevels type-checks the compute package and returns every
// exported constant of type compute.AccessLevel.
func computeAccessLevels(tb testing.TB) []string {
	tb.Helper()
	const dir = "../../compute"
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatalf("reading %s: %v", dir, err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			tb.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		tb.Fatal("no non-test Go files in the compute package; a derivation that returns " +
			"nothing passes every check over it")
	}

	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("github.com/conductorone/apphub/compute", fset, files, nil)
	if err != nil {
		tb.Fatalf("type-checking compute: %v", err)
	}
	want := fmt.Sprintf("%s.AccessLevel", pkg.Path())
	var out []string
	for _, name := range pkg.Scope().Names() {
		c, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || !c.Exported() || c.Type().String() != want {
			continue
		}
		out = append(out, strings.Trim(c.Val().String(), `"`))
	}
	sort.Strings(out)
	return out
}
