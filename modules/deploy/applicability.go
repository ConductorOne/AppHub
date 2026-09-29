// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Applicability: which fields of an application record carry meaning under
// which circumstances, and what happens to one that does not.
//
// # Why this is a table and a walk rather than a handful of checks
//
// A field that belongs to one variant and is set on another was previously
// *ignored*: a zone on a non-zonal bucket, a schedule on a service, a function
// runtime on a container. Ignoring is the wrong answer twice over. It discards
// what the operator asked for without telling them, and — the half review
// found — some of those fields are not ignored all the way down. A zone on a
// standard bucket travelled into [github.com/conductorone/apphub/compute.BucketSpec]
// and was refused by the provider, *after* this module had already marked the
// record as deploying and created three resources. A rejected plan that
// partially applies leaves real infrastructure nobody asked for and nothing
// recorded.
//
// Three hand-placed checks would have closed the three cases review reproduced.
// They would not have closed the fourth field somebody adds next month, and
// that is the actual defect: the input types can express a combination the
// module cannot honour, and nothing systematically says so.
//
// So the rule is stated once, over a population derived from the types
// themselves:
//
//	every exported field of every input type is classified, and a field whose
//	condition does not hold must be zero.
//
// An unclassified field is **fatal**, not absent — see [checkApplicability].
// That is what makes adding a field a decision somebody makes rather than a
// gap: the build stops until the new field is classified, and classifying it is
// where the thought happens.
//
// # The types are reached, not listed
//
// The first version of this walked four hand-listed structs. Review defeated it
// by adding a nested type: the outer field was classified, the derived count
// rose from 43 to 44, and the nested type's own fields stayed outside the
// population entirely — *the count rose without the coverage rising*, which is
// the failure this whole construction exists to prevent, one level down.
//
// So [checkApplicability] reaches types rather than listing them. It walks the
// field graph from [Application], descending into every struct this package
// owns — through slices, arrays and maps as well as plain fields — and requires
// each one to have either field classifications or an explicit whole-type
// decision in [wholeTypeDecisions]. A type nobody has ruled on is fatal.
//
// It deliberately does **not** descend into types this package does not own.
// A [github.com/conductorone/apphub/compute.Ref] or a time.Time is a value from
// somebody else's package, and classifying its fields would be this package
// ruling on a type it does not define. That boundary is the ownership test —
// `reflect.Type.PkgPath` — not a name list.

// condition names a circumstance under which a field carries meaning.
//
// Name is not decoration: it is what the refusal tells an operator, and it is
// what distinguishes "this field is unconditional" from "this field is an
// output the module writes", which are the same predicate and different facts.
//
// holds receives the application and the struct the field belongs to. Most
// conditions are properties of the application; a route's are properties of the
// route, and a single signature keeps them in one table rather than two that
// have to be kept in step.
type condition struct {
	name  string
	holds func(app *Application, enclosing reflect.Value) bool
}

func appCondition(name string, f func(*Application) bool) condition {
	return condition{name, func(a *Application, _ reflect.Value) bool { return f(a) }}
}

var (
	// always is an input that applies to every application.
	always = appCondition("every application", func(*Application) bool { return true })
	// output is written by this module, not read from the record. A redeploy
	// legitimately carries the previous deploy's values, so it is unconstrained
	// — but it is named separately so the table says which fields are inputs.
	output = appCondition("written by the module, never read as input",
		func(*Application) bool { return true })

	scheduled = appCondition("a scheduled application", func(a *Application) bool {
		return a.Execution == ExecutionScheduled
	})
	functionWorkload = appCondition("a function application", func(a *Application) bool {
		return a.Workload == WorkloadFunction
	})
	relationalDatabase = appCondition("an application with a relational database", func(a *Application) bool {
		return a.Database.Kind == DatabaseRelational
	})
	keyValueDatabase = appCondition("an application with a key-value table", func(a *Application) bool {
		return a.Database.Kind == DatabaseKeyValue
	})
	anyBucket = appCondition("an application with a bucket", func(a *Application) bool {
		return a.Bucket.Kind != BucketNone
	})
	zonalBucket = appCondition("an application with a zonal bucket", func(a *Application) bool {
		return a.Bucket.Kind == BucketZonal
	})

	// authenticatedRoute is the one condition that is a property of the
	// enclosing struct rather than of the application: paths exempt from
	// authentication mean nothing on a route that does not require it, and a
	// record carrying them is a record whose author believed it did.
	authenticatedRoute = condition{"a route that requires authentication",
		func(_ *Application, enclosing reflect.Value) bool {
			r, ok := enclosing.Interface().(Route)
			return ok && r.RequireAuth
		}}
)

// inputFields classifies every exported field of every type the walk reaches
// from [Application]. Keyed "Type.Field".
//
// The walk derives which keys it needs from the types, so this table cannot
// fall behind them: a field with no entry stops the check.
var inputFields = map[string]condition{
	// Application.
	"Application.ID":             always,
	"Application.Name":           always,
	"Application.Source":         always,
	"Application.Workload":       always,
	"Application.Execution":      always,
	"Application.Schedule":       scheduled,
	"Application.Resources":      always,
	"Application.Replicas":       always,
	"Application.Port":           always,
	"Application.Runtime":        functionWorkload,
	"Application.Handler":        functionWorkload,
	"Application.Database":       always,
	"Application.Bucket":         always,
	"Application.Secrets":        always,
	"Application.EnvSecrets":     always,
	"Application.PinnedImage":    always,
	"Application.Capabilities":   always,
	"Application.Routes":         always,
	"Application.Labels":         always,
	"Application.Status":         output,
	"Application.DeployStep":     output,
	"Application.FailedStep":     output,
	"Application.FailureClass":   output,
	"Application.LastDeployedAt": output,
	"Application.Artifacts":      output,

	// Source.
	"Source.URL":        always,
	"Source.Ref":        always,
	"Source.Dockerfile": always,

	// Database.
	"Database.Kind":          always,
	"Database.Engine":        relationalDatabase,
	"Database.EngineVersion": relationalDatabase,
	"Database.DatabaseName":  relationalDatabase,
	"Database.AdminUsername": relationalDatabase,
	"Database.Capacity":      relationalDatabase,
	"Database.Extensions":    relationalDatabase,
	"Database.PartitionKey":  keyValueDatabase,
	"Database.SortKey":       keyValueDatabase,

	// Bucket.
	"Bucket.Kind":   always,
	"Bucket.Name":   anyBucket,
	"Bucket.Zone":   zonalBucket,
	"Bucket.Access": anyBucket,

	// Route.
	"Route.Hostname":             always,
	"Route.Internal":             always,
	"Route.RequireAuth":          always,
	"Route.AllowPlaintext":       always,
	"Route.PublicPaths":          authenticatedRoute,
	"Route.MCPAuthApplicationID": always,
	// SecretBinding. Both are required, so the entries exist for the
	// completeness check rather than for the zero check.
	"SecretBinding.EnvName": always,
	"SecretBinding.Secret":  always,
}

// wholeTypeDecisions rules on a type this package owns without classifying its
// fields one by one, with the reason.
//
// It is the escape hatch that keeps the walk honest rather than the one that
// makes it toothless: a type has to be *named here*, with a reason, or every
// one of its exported fields has to be classified. What is not available is
// silence.
var wholeTypeDecisions = map[string]string{
	"Artifacts": "every field is written by this module and never read from the record, " +
		"so there is no combination of them an operator can get wrong; a redeploy " +
		"legitimately carries all of them",
}

// checkApplicability refuses an application record that sets a field outside
// the circumstance in which the field means anything.
//
// It is the whole of the rule. Nothing else in this package repeats it, and a
// field or a type reached from [Application] without a decision stops here with
// a message naming it — because a walk that shrugs at an input it does not
// recognise is a gate with a bypass, and this one is the gate that decides
// whether a record is deployable at all.
func checkApplicability(app *Application) error {
	return applicability(app, inputFields, wholeTypeDecisions)
}

// packagePath is the import path of this package, and the ownership test the
// walk uses to decide whether to descend into a struct.
var packagePath = reflect.TypeOf(Application{}).PkgPath()

// applicability is [checkApplicability] over supplied tables.
//
// The tables are parameters so a test can drive the fail-closed paths with a
// table missing an entry, without mutating the package-level ones. A test that
// reached in and deleted a key would be sharing mutable state with every other
// test in the package, and the two that did it raced immediately.
func applicability(app *Application, fields map[string]condition, whole map[string]string) error {
	w := &applicabilityWalk{app: app, fields: fields, whole: whole, seen: map[reflect.Type]bool{}}
	w.walk(reflect.ValueOf(*app), "")
	if len(w.problems) == 0 {
		return nil
	}
	sort.Strings(w.problems)
	return fmt.Errorf("%w: %s", ErrInvalidApplication, strings.Join(w.problems, "; "))
}

// applicabilityWalk carries the state of one traversal.
type applicabilityWalk struct {
	app      *Application
	fields   map[string]condition
	whole    map[string]string
	problems []string
	// seen bounds the traversal on the TYPE graph rather than the value graph,
	// so a type that refers to itself terminates. It is only consulted for
	// classification, which is a property of the type; the zero check below
	// still visits every value.
	seen map[reflect.Type]bool
}

// walk classifies one struct value's fields and descends into the structs this
// package owns beneath it.
//
// where is a human-readable path to the value, empty at the root, so a refusal
// about the third route says so.
func (w *applicabilityWalk) walk(v reflect.Value, where string) {
	rt := v.Type()
	name := rt.Name()
	if reason, ruled := w.whole[name]; ruled {
		_ = reason // The decision is the entry; nothing below it is checked.
		return
	}

	classified := false
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		classified = true
		key := name + "." + f.Name
		cond, known := w.fields[key]
		if !known {
			w.problems = append(w.problems, fmt.Sprintf("%s%s is not classified: this module "+
				"cannot say when it applies, so it cannot say whether the record is "+
				"deployable. Add it to the applicability table", prefix(where), key))
			continue
		}
		if !cond.holds(w.app, v) && !v.Field(i).IsZero() {
			w.problems = append(w.problems, fmt.Sprintf("%s%s is set, and it applies only to %s",
				prefix(where), key, cond.name))
		}
		w.descend(v.Field(i), where, key)
	}

	// A struct this package owns with no exported fields and no whole-type
	// decision is a type nobody has ruled on. Silence is the one answer this
	// walk does not accept.
	if !classified && !w.seen[rt] {
		w.seen[rt] = true
		w.problems = append(w.problems, fmt.Sprintf("%stype %s is reached from the application "+
			"record and has no classified fields and no whole-type decision", prefix(where), name))
	}
}

// descend follows a value into the structs this package owns beneath it,
// through slices, arrays and maps as well as plain fields.
//
// A struct this package does NOT own is a leaf: a compute.Ref or a time.Time is
// somebody else's type, and ruling on its fields would be this package deciding
// something it does not define.
func (w *applicabilityWalk) descend(v reflect.Value, where, key string) {
	switch v.Kind() {
	case reflect.Struct:
		if v.Type().PkgPath() == packagePath {
			w.walk(v, key)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			w.descend(v.Elem(), where, key)
		}
	case reflect.Slice, reflect.Array:
		w.element(v.Type().Elem(), key)
		for i := 0; i < v.Len(); i++ {
			w.descend(v.Index(i), where, fmt.Sprintf("%s[%d]", key, i))
		}
	case reflect.Map:
		w.element(v.Type().Elem(), key)
		iter := v.MapRange()
		for iter.Next() {
			w.descend(iter.Value(), where, key)
		}
	default:
	}
}

// element classifies a collection's element type even when the collection is
// empty.
//
// Without it, a field added to a nested type would go unclassified on every
// record that happens not to populate the collection — which is most of them,
// and would make the fatal-on-unclassified rule depend on the fixture rather
// than on the types.
func (w *applicabilityWalk) element(rt reflect.Type, key string) {
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct || rt.PkgPath() != packagePath || w.seen[rt] {
		return
	}
	w.seen[rt] = true
	w.walk(reflect.New(rt).Elem(), key)
}

func prefix(where string) string {
	if where == "" {
		return ""
	}
	return where + ": "
}
